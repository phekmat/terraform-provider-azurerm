package azurerm

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/terraform-providers/terraform-provider-azurerm/azurerm/utils"
)

func TestAccAzureRMKeyVaultKey_basicEC(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_basicEC(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
				),
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_basicECHSM(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_basicECHSM(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
				),
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_curveEC(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_curveEC(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
				),
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_basicRSA(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_basicRSA(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
				),
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_basicRSAHSM(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_basicRSAHSM(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
				),
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_complete(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_complete(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "tags.%", "1"),
					resource.TestCheckResourceAttr(resourceName, "tags.hello", "world"),
				),
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_update(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_basicRSA(rs, testLocation())
	updatedConfig := testAccAzureRMKeyVaultKey_basicUpdated(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "key_opts.#", "6"),
					resource.TestCheckResourceAttr(resourceName, "key_opts.0", "decrypt"),
				),
			},
			{
				Config: updatedConfig,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
					resource.TestCheckResourceAttr(resourceName, "key_opts.#", "5"),
					resource.TestCheckResourceAttr(resourceName, "key_opts.0", "encrypt"),
				),
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_disappears(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_basicEC(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
					testCheckAzureRMKeyVaultKeyDisappears(resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_disappearsWhenParentKeyVaultDeleted(t *testing.T) {
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_basicEC(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists("azurerm_key_vault_key.test"),
					testCheckAzureRMKeyVaultDisappears("azurerm_key_vault.test"),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_importRSA(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_basicRSA(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_importEC(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_curveEC(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccAzureRMKeyVaultKey_basicRSAImport(t *testing.T) {
	resourceName := "azurerm_key_vault_key.test"
	rs := acctest.RandString(6)
	config := testAccAzureRMKeyVaultKey_basicRSAImport(rs, testLocation())

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testCheckAzureRMKeyVaultKeyDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					testCheckAzureRMKeyVaultKeyExists(resourceName),
				),
			},
		},
	})
}

func testCheckAzureRMKeyVaultKeyDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(*ArmClient).keyVaultManagementClient
	ctx := testAccProvider.Meta().(*ArmClient).StopContext

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "azurerm_key_vault_key" {
			continue
		}

		name := rs.Primary.Attributes["name"]
		vaultBaseUrl := rs.Primary.Attributes["vault_uri"]

		// get the latest version
		resp, err := client.GetKey(ctx, vaultBaseUrl, name, "")
		if err != nil {
			if utils.ResponseWasNotFound(resp.Response) {
				return nil
			}
			return err
		}

		return fmt.Errorf("Key Vault Key still exists:\n%#v", resp)
	}

	return nil
}

func testCheckAzureRMKeyVaultKeyExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Ensure we have enough information in state to look up in API
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}
		name := rs.Primary.Attributes["name"]
		vaultBaseUrl := rs.Primary.Attributes["vault_uri"]

		client := testAccProvider.Meta().(*ArmClient).keyVaultManagementClient
		ctx := testAccProvider.Meta().(*ArmClient).StopContext

		resp, err := client.GetKey(ctx, vaultBaseUrl, name, "")
		if err != nil {
			if utils.ResponseWasNotFound(resp.Response) {
				return fmt.Errorf("Bad: Key Vault Key %q (resource group: %q) does not exist", name, vaultBaseUrl)
			}

			return fmt.Errorf("Bad: Get on keyVaultManagementClient: %+v", err)
		}

		return nil
	}
}

func testCheckAzureRMKeyVaultKeyDisappears(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		// Ensure we have enough information in state to look up in API
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		name := rs.Primary.Attributes["name"]
		vaultBaseUrl := rs.Primary.Attributes["vault_uri"]

		client := testAccProvider.Meta().(*ArmClient).keyVaultManagementClient
		ctx := testAccProvider.Meta().(*ArmClient).StopContext

		resp, err := client.DeleteKey(ctx, vaultBaseUrl, name)
		if err != nil {
			if utils.ResponseWasNotFound(resp.Response) {
				return nil
			}

			return fmt.Errorf("Bad: Delete on keyVaultManagementClient: %+v", err)
		}

		return nil
	}
}

func testAccAzureRMKeyVaultKey_basicEC(rString string, location string) string {
	return fmt.Sprintf(`
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%s"
  location = "%s"
}

resource "azurerm_key_vault" "test" {
  name                = "acctestkv-%s"
  location            = "${azurerm_resource_group.test.location}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  tenant_id           = "${data.azurerm_client_config.current.tenant_id}"

  sku {
    name = "premium"
  }

  access_policy {
    tenant_id = "${data.azurerm_client_config.current.tenant_id}"
    object_id = "${data.azurerm_client_config.current.service_principal_object_id}"

    key_permissions = [
      "create",
      "delete",
      "get",
    ]

    secret_permissions = [
      "get",
      "delete",
      "set",
    ]
  }

  tags {
    environment = "Production"
  }
}

resource "azurerm_key_vault_key" "test" {
  name      = "key-%s"
  vault_uri = "${azurerm_key_vault.test.vault_uri}"
  key_type  = "EC"
  key_size  = 2048

  key_opts = [
    "sign",
    "verify",
  ]
}
`, rString, location, rString, rString)
}

func testAccAzureRMKeyVaultKey_basicRSA(rString string, location string) string {
	return fmt.Sprintf(`
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%s"
  location = "%s"
}

resource "azurerm_key_vault" "test" {
  name                = "acctestkv-%s"
  location            = "${azurerm_resource_group.test.location}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  tenant_id           = "${data.azurerm_client_config.current.tenant_id}"

  sku {
    name = "premium"
  }

  access_policy {
    tenant_id = "${data.azurerm_client_config.current.tenant_id}"
    object_id = "${data.azurerm_client_config.current.service_principal_object_id}"

    key_permissions = [
      "create",
      "delete",
      "get",
      "update",
    ]

    secret_permissions = [
      "get",
      "delete",
      "set",
    ]
  }

  tags {
    environment = "Production"
  }
}

resource "azurerm_key_vault_key" "test" {
  name      = "key-%s"
  vault_uri = "${azurerm_key_vault.test.vault_uri}"
  key_type  = "RSA"
  key_size  = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
`, rString, location, rString, rString)
}

func testAccAzureRMKeyVaultKey_basicRSAHSM(rString string, location string) string {
	return fmt.Sprintf(`
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%s"
  location = "%s"
}

resource "azurerm_key_vault" "test" {
  name                = "acctestkv-%s"
  location            = "${azurerm_resource_group.test.location}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  tenant_id           = "${data.azurerm_client_config.current.tenant_id}"

  sku {
    name = "premium"
  }

  access_policy {
    tenant_id = "${data.azurerm_client_config.current.tenant_id}"
    object_id = "${data.azurerm_client_config.current.service_principal_object_id}"

    key_permissions = [
      "create",
      "delete",
      "get",
    ]

    secret_permissions = [
      "get",
      "delete",
      "set",
    ]
  }

  tags {
    environment = "Production"
  }
}

resource "azurerm_key_vault_key" "test" {
  name      = "key-%s"
  vault_uri = "${azurerm_key_vault.test.vault_uri}"
  key_type  = "RSA-HSM"
  key_size  = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
`, rString, location, rString, rString)
}

func testAccAzureRMKeyVaultKey_complete(rString string, location string) string {
	return fmt.Sprintf(`
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%s"
  location = "%s"
}

resource "azurerm_key_vault" "test" {
  name                = "acctestkv-%s"
  location            = "${azurerm_resource_group.test.location}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  tenant_id           = "${data.azurerm_client_config.current.tenant_id}"

  sku {
    name = "premium"
  }

  access_policy {
    tenant_id = "${data.azurerm_client_config.current.tenant_id}"
    object_id = "${data.azurerm_client_config.current.service_principal_object_id}"

    key_permissions = [
      "create",
      "delete",
      "get",
    ]

    secret_permissions = [
      "get",
      "delete",
      "set",
    ]
  }

  tags {
    environment = "Production"
  }
}

resource "azurerm_key_vault_key" "test" {
  name      = "key-%s"
  vault_uri = "${azurerm_key_vault.test.vault_uri}"
  key_type  = "RSA"
  key_size  = 2048

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]

  tags {
    "hello" = "world"
  }
}
`, rString, location, rString, rString)
}

func testAccAzureRMKeyVaultKey_basicUpdated(rString string, location string) string {
	return fmt.Sprintf(`
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%s"
  location = "%s"
}

resource "azurerm_key_vault" "test" {
  name                = "acctestkv-%s"
  location            = "${azurerm_resource_group.test.location}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  tenant_id           = "${data.azurerm_client_config.current.tenant_id}"

  sku {
    name = "premium"
  }

  access_policy {
    tenant_id = "${data.azurerm_client_config.current.tenant_id}"
    object_id = "${data.azurerm_client_config.current.service_principal_object_id}"

    key_permissions = [
      "create",
      "delete",
      "get",
      "update",
    ]

    secret_permissions = [
      "get",
      "delete",
      "set",
    ]
  }

  tags {
    environment = "Production"
  }
}

resource "azurerm_key_vault_key" "test" {
  name      = "key-%s"
  vault_uri = "${azurerm_key_vault.test.vault_uri}"
  key_type  = "RSA"
  key_size  = 2048

  key_opts = [
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
`, rString, location, rString, rString)
}

func testAccAzureRMKeyVaultKey_curveEC(rString string, location string) string {
	return fmt.Sprintf(`
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%s"
  location = "%s"
}

resource "azurerm_key_vault" "test" {
  name                = "acctestkv-%s"
  location            = "${azurerm_resource_group.test.location}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  tenant_id           = "${data.azurerm_client_config.current.tenant_id}"

  sku {
    name = "premium"
  }

  access_policy {
    tenant_id = "${data.azurerm_client_config.current.tenant_id}"
    object_id = "${data.azurerm_client_config.current.service_principal_object_id}"

    key_permissions = [
      "create",
      "delete",
      "get",
    ]

    secret_permissions = [
      "get",
      "delete",
      "set",
    ]
  }

  tags {
    environment = "Production"
  }
}

resource "azurerm_key_vault_key" "test" {
  name      = "key-%s"
  vault_uri = "${azurerm_key_vault.test.vault_uri}"
  key_type  = "EC"
  curve     = "P-521"

  key_opts = [
    "sign",
    "verify",
  ]
}
`, rString, location, rString, rString)
}

func testAccAzureRMKeyVaultKey_basicECHSM(rString string, location string) string {
	return fmt.Sprintf(`
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%s"
  location = "%s"
}

resource "azurerm_key_vault" "test" {
  name                = "acctestkv-%s"
  location            = "${azurerm_resource_group.test.location}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  tenant_id           = "${data.azurerm_client_config.current.tenant_id}"

  sku {
    name = "premium"
  }

  access_policy {
    tenant_id = "${data.azurerm_client_config.current.tenant_id}"
    object_id = "${data.azurerm_client_config.current.service_principal_object_id}"

    key_permissions = [
      "create",
      "delete",
      "get",
    ]

    secret_permissions = [
      "get",
      "delete",
      "set",
    ]
  }

  tags {
    environment = "Production"
  }
}

resource "azurerm_key_vault_key" "test" {
  name      = "key-%s"
  vault_uri = "${azurerm_key_vault.test.vault_uri}"
  key_type  = "EC-HSM"
  curve     = "P-521"

  key_opts = [
    "sign",
    "verify",
  ]
}
`, rString, location, rString, rString)
}
func testAccAzureRMKeyVaultKey_basicRSAImport(rString string, location string) string {
	return fmt.Sprintf(`
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "test" {
  name     = "acctestRG-%s"
  location = "%s"
}

resource "azurerm_key_vault" "test" {
  name                = "acctestkv-%s"
  location            = "${azurerm_resource_group.test.location}"
  resource_group_name = "${azurerm_resource_group.test.name}"
  tenant_id           = "${data.azurerm_client_config.current.tenant_id}"

  sku {
    name = "premium"
  }

  access_policy {
    tenant_id = "${data.azurerm_client_config.current.tenant_id}"
    object_id = "${data.azurerm_client_config.current.service_principal_object_id}"

    key_permissions = [
      "create",
      "delete",
      "get",
      "update",
      "import",
    ]

    secret_permissions = [
      "get",
      "delete",
      "set",
    ]
  }

  tags {
    environment = "Production"
  }
}

resource "azurerm_key_vault_key" "test" {
  name      = "key-%s"
  vault_uri = "${azurerm_key_vault.test.vault_uri}"
  key_type  = "RSA"
	key_size  = 2048
	key_data  = <<EOF
-----BEGIN RSA PRIVATE KEY-----
	MIIEpQIBAAKCAQEAsihjrmgaiZdBsI+yoy6yNdhOGlooQm92pWWOYnU6kslZEA/B
	zpKhBhP/glt6cNhd5MzOih7jRaT2xkOF7fInoOmlhn/kfkIFJgjV0vx7mlxHW1FA
	hpe2abAoq/p7bE2DyMlerMLg9PsAva5asQL+rFuEvk56orQ+Io86vuqIu7mkLim+
	1sa6fjrKVQAwuwvATx82AWvyu3XZcGGdFXOM1c93vDnlB6hirMHd0ZBBM3g7hG9w
	GzgVxDdOCHMQ+i8hSYd7RGdKSMvqywv7/lQCxfL1rMaMCCVRtK5bBt+SFgokNtVY
	2ugvRkarKN2gqZneST7glnbNpva2MofsdocNawIDAQABAoIBAQCcLpY8dh0Vk9lN
	nJvhPHWUiJznszPqEec0VhR9sgF4XzVJxFaF7rtlJbDwKZvsQ3IEu5sxMKTTECwa
	YWWO1KPzCAFJKOM54Ey9LC+veBIvn0gbAN8NXwDWJE1zfvImXsnyAr6Ru4IUodrj
	bm8pENQMa2qynwAZlOOHzoKUjezyi/R1erLgA70HGyo89VZ9NS2bckilStUrJ6sO
	6o09ZeFUS5Kruq1FiUSepHAgfxPTDnMSF0COIIRSBMUVcBTQaas2ZvgEYq7Jluh9
	rhOnNjwV0ZYUb9DURBvem2rkvaucogC7hN3BjULpc+afs4ZROkkEaMKzLhXC1euD
	XeZy1n15AoGBAN2LtjPAVplxcfsUMcSKUeRMTO5gIKdrs9alL3mDh6VwNGxpnjSk
	hUsE6NPKHCrFUdbnB7nww0o299zu32IWx8PVr3U9SQ7bnbzudCxh52mV8Tg8yMLK
	zgCPXQX0R+q/ZnaJHImjEKSEmIFgrmDIuak0rljlU5hy9xVD90t3zpO/AoGBAM3d
	S00fNE4cv62WwsufYPd6dMK/AyTAQAeDqNLIJfN2ZCGC5PAr2xcV8R1vOn/NAjTv
	at0JZM0b4Mp4IzHozDA/eUzI2pZuTNbZsJMuEmy6JuSeCuzT7hwvac5ORonVytES
	wmNisYcCr+MkKAo4+4CpR0akSbTSj2hIqOMds8FVAoGBALKucPhSQ0YkijJfujfy
	+1Nu+okzfIKrSfNvbNfLbobO9WkO0itRGbREtGfEVW1lkbkKwl+EQG3F4akN+5qI
	Fvvqh0W+dQMHu7PaelYlbFfrOA8Mbzs0CGvJNNSNjcdWMZSexyZ3HwAhdUK7sEic
	+6jttUQ7SW3mI0PCelwit7jPAoGAQm7gZwHj4jU60ezt7cIAC7zzwwjbHdgAkaw2
	Jdc7EAcrpvjTooG0kQ2eoq4LRcTFqol8hdoLMnmFoDEGwotqoUNKhLHogFUV7NuR
	NN3QSlAETxCFXAnENEpErbPq5X4dljykiGgH/Bas5fL8DNh4qPt3qd9IfdbZOoEA
	J1KleIUCgYEAue6TpHMSYTgVbn4sYg7nTyRqOdlqyqNsDzDAe6bH26ZSKlvbbXQy
	qOq8JO6s7WzmGXnvcUNCswJ+OBiv38/uRipxn0zdVYnGA+g3Qnm3gTUZxGYlJfD1
	Ic/BaNaH8kAnmEXuNHxWYAmfnD0Z5AbPGTlN3YSeFUt5vhmA3N8CEfA=
-----END RSA PRIVATE KEY-----
EOF

  key_opts = [
    "decrypt",
    "encrypt",
    "sign",
    "unwrapKey",
    "verify",
    "wrapKey",
  ]
}
`, rString, location, rString, rString)
}
