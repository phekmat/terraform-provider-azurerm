package azurerm

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/2016-10-01/keyvault"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func resourceArmKeyVaultKey() *schema.Resource {
	return &schema.Resource{
		Create: resourceArmKeyVaultKeyCreate,
		Read:   resourceArmKeyVaultKeyRead,
		Update: resourceArmKeyVaultKeyUpdate,
		Delete: resourceArmKeyVaultKeyDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validateKeyVaultChildName,
			},

			"vault_uri": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},

			"key_type": {
				Type:     schema.TypeString,
				Required: true,
				// turns out Azure's *really* sensitive about the casing of these
				// issue: https://github.com/Azure/azure-rest-api-specs/issues/1739
				ValidateFunc: validation.StringInSlice([]string{
					// TODO: add `oct` back in once this is fixed
					// https://github.com/Azure/azure-rest-api-specs/issues/1739#issuecomment-332236257
					string(keyvault.EC),
					string(keyvault.ECHSM),
					string(keyvault.RSA),
					string(keyvault.RSAHSM),
				}, false),
			},

			"key_size": {
				Type:             schema.TypeInt,
				Optional:         true,
				DiffSuppressFunc: ignoreKeySizeChangesForEC,
				ConflictsWith:    []string{"curve"},
			},

			"key_opts": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
					// turns out Azure's *really* sensitive about the casing of these
					// issue: https://github.com/Azure/azure-rest-api-specs/issues/1739
					ValidateFunc: validation.StringInSlice([]string{
						string(keyvault.Decrypt),
						string(keyvault.Encrypt),
						string(keyvault.Sign),
						string(keyvault.UnwrapKey),
						string(keyvault.Verify),
						string(keyvault.WrapKey),
					}, false),
				},
			},

			"curve": {
				Type:     schema.TypeString,
				Optional: true,
				ValidateFunc: validation.StringInSlice([]string{
					string(keyvault.P256),
					string(keyvault.P384),
					string(keyvault.P521),
					string(keyvault.SECP256K1),
				}, false),
				// TODO: the curve name should probably be mandatory for EC in the future,
				// but handle the diff so that we don't break existing configurations and
				// imported EC keys
				DiffSuppressFunc: ignoreEmptyCurveChanges,
				ConflictsWith:    []string{"key_size"},
			},

			"key_data": {
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
			},

			// Computed
			"version": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"n": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"e": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"x": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"y": {
				Type:     schema.TypeString,
				Computed: true,
			},

			"tags": tagsSchema(),
		},
	}
}

func ignoreKeySizeChangesForEC(k, old, new string, d *schema.ResourceData) bool {
	keyType := keyvault.JSONWebKeyType(d.Get("key_type").(string))
	if keyType == keyvault.EC || keyType == keyvault.ECHSM {
		return true
	}
	return old == new
}

func ignoreEmptyCurveChanges(k, old, new string, d *schema.ResourceData) bool {
	return new == "" || old == new
}

func resourceArmKeyVaultKeyCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).keyVaultManagementClient
	ctx := meta.(*ArmClient).StopContext

	log.Print("[INFO] preparing arguments for AzureRM KeyVault Key creation.")
	name := d.Get("name").(string)
	keyVaultBaseUrl := d.Get("vault_uri").(string)

	keyType := d.Get("key_type").(string)
	keyOptions := expandKeyVaultKeyOptions(d)
	tags := d.Get("tags").(map[string]interface{})

	// TODO: support Importing Keys once this is fixed:
	// https://github.com/Azure/azure-rest-api-specs/issues/1747
	parameters := keyvault.KeyCreateParameters{
		Kty:    keyvault.JSONWebKeyType(keyType),
		KeyOps: keyOptions,
		KeyAttributes: &keyvault.KeyAttributes{
			Enabled: utils.Bool(true),
		},

		Tags: expandTags(tags),
	}

	if parameters.Kty == keyvault.EC || parameters.Kty == keyvault.ECHSM {
		curveName := d.Get("curve").(string)
		parameters.Curve = keyvault.JSONWebKeyCurveName(curveName)
	} else if parameters.Kty == keyvault.RSA || parameters.Kty == keyvault.RSAHSM {
		keySize, ok := d.GetOk("key_size")
		if !ok {
			return fmt.Errorf("Key size is required when creating an RSA key")
		}
		parameters.KeySize = utils.Int32(int32(keySize.(int)))
	}
	// TODO: support `oct` once this is fixed
	// https://github.com/Azure/azure-rest-api-specs/issues/1739#issuecomment-332236257

	if keyData, ok := d.GetOk("key_data"); ok {
		stringKeyOpts := make([]string, 0, len(*keyOptions))
		for _, opt := range *keyOptions {
			stringKeyOpts = append(stringKeyOpts, string(opt))
		}
		pem, _ := pem.Decode([]byte(strings.TrimSpace(keyData.(string))))
		if pem == nil {
			return fmt.Errorf("Could not decode private key: +%v", keyData.(string))
		}
		key, err := x509.ParsePKCS1PrivateKey(pem.Bytes)
		if err != nil {
			return fmt.Errorf("Could not decode private key: %+v", err)
		}

		webKey := rsaPrivateKeyToJSONWebKey(key)
		webKey.KeyOps = &stringKeyOpts
		webKey.Kty = keyvault.JSONWebKeyType(keyType)
		hsm := webKey.Kty == keyvault.RSAHSM
		importParameters := keyvault.KeyImportParameters{
			Hsm: &hsm,
			Key: &webKey,
			KeyAttributes: &keyvault.KeyAttributes{
				Enabled: utils.Bool(true),
			},
			Tags: expandTags(tags),
		}
		_, err = client.ImportKey(ctx, keyVaultBaseUrl, name, importParameters)
		if err != nil {
			return fmt.Errorf("Error Importing Key: %+v", err)
		}
	} else {
		_, err := client.CreateKey(ctx, keyVaultBaseUrl, name, parameters)
		if err != nil {
			return fmt.Errorf("Error Creating Key: %+v", err)
		}
	}

	// "" indicates the latest version
	read, err := client.GetKey(ctx, keyVaultBaseUrl, name, "")
	if err != nil {
		return err
	}

	d.SetId(*read.Key.Kid)

	return resourceArmKeyVaultKeyRead(d, meta)
}

func resourceArmKeyVaultKeyUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).keyVaultManagementClient
	ctx := meta.(*ArmClient).StopContext

	log.Print("[INFO] preparing arguments for AzureRM KeyVault Key update.")
	id, err := parseKeyVaultChildID(d.Id())
	if err != nil {
		return err
	}
	if d.HasChange("key_size") || d.HasChange("key_type") || d.HasChange("curve") || d.HasChange("key_data") {
		return resourceArmKeyVaultKeyCreate(d, meta)
	}
	keyOptions := expandKeyVaultKeyOptions(d)
	tags := d.Get("tags").(map[string]interface{})

	parameters := keyvault.KeyUpdateParameters{
		KeyOps: keyOptions,
		KeyAttributes: &keyvault.KeyAttributes{
			Enabled: utils.Bool(true),
		},
		Tags: expandTags(tags),
	}

	_, err = client.UpdateKey(ctx, id.KeyVaultBaseUrl, id.Name, id.Version, parameters)
	if err != nil {
		return err
	}

	return resourceArmKeyVaultKeyRead(d, meta)
}

func resourceArmKeyVaultKeyRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).keyVaultManagementClient
	ctx := meta.(*ArmClient).StopContext

	id, err := parseKeyVaultChildID(d.Id())
	if err != nil {
		return err
	}

	resp, err := client.GetKey(ctx, id.KeyVaultBaseUrl, id.Name, "")
	if err != nil {
		if utils.ResponseWasNotFound(resp.Response) {
			log.Printf("[DEBUG] Key %q was not found in Key Vault at URI %q - removing from state", id.Name, id.KeyVaultBaseUrl)
			d.SetId("")
			return nil
		}

		return err
	}

	d.Set("name", id.Name)
	d.Set("vault_uri", id.KeyVaultBaseUrl)

	if key := resp.Key; key != nil {
		d.Set("key_type", string(key.Kty))

		options := flattenKeyVaultKeyOptions(key.KeyOps)
		if err := d.Set("key_opts", options); err != nil {
			return err
		}

		d.Set("n", key.N)
		d.Set("e", key.E)
		d.Set("x", key.X)
		d.Set("y", key.Y)
		if key.N != nil {
			nBytes, err := base64.RawURLEncoding.DecodeString(*key.N)
			if err != nil {
				return fmt.Errorf("Could not decode N: %+v", err)
			}
			d.Set("key_size", len(nBytes)*8)
		}

		d.Set("curve", key.Crv)
	}

	// Computed
	d.Set("version", id.Version)

	flattenAndSetTags(d, resp.Tags)

	return nil
}

func resourceArmKeyVaultKeyDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*ArmClient).keyVaultManagementClient
	ctx := meta.(*ArmClient).StopContext

	id, err := parseKeyVaultChildID(d.Id())
	if err != nil {
		return err
	}

	_, err = client.DeleteKey(ctx, id.KeyVaultBaseUrl, id.Name)

	return err
}

func expandKeyVaultKeyOptions(d *schema.ResourceData) *[]keyvault.JSONWebKeyOperation {
	options := d.Get("key_opts").([]interface{})
	results := make([]keyvault.JSONWebKeyOperation, 0, len(options))

	for _, option := range options {
		results = append(results, keyvault.JSONWebKeyOperation(option.(string)))
	}

	return &results
}

func flattenKeyVaultKeyOptions(input *[]string) []interface{} {
	results := make([]interface{}, 0, len(*input))

	for _, option := range *input {
		results = append(results, option)
	}

	return results
}

func rsaPrivateKeyToJSONWebKey(key *rsa.PrivateKey) keyvault.JSONWebKey {
	// Compute DP, DQ, QI
	key.Precompute()
	encode := base64.URLEncoding.EncodeToString

	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, uint32(key.E))
	e := encode(bytes)

	d := encode(key.D.Bytes())
	n := encode(key.N.Bytes())
	dp := encode(key.Precomputed.Dp.Bytes())
	dq := encode(key.Precomputed.Dq.Bytes())
	p := encode(key.Primes[0].Bytes())
	q := encode(key.Primes[1].Bytes())
	qi := encode(key.Precomputed.Qinv.Bytes())
	jwk := keyvault.JSONWebKey{
		N:  &n,
		E:  &e,
		Q:  &q,
		P:  &p,
		D:  &d,
		DP: &dp,
		DQ: &dq,
		QI: &qi,
	}

	return jwk
}
