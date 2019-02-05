# Terraform LDAP 

[![CircleCI](https://circleci.com/gh/dihedron/terraform-provider-ldap/tree/feature%2Ftest-circleci-2.0.svg?style=svg)](https://circleci.com/gh/dihedron/terraform-provider-ldap/tree/feature%2Ftest-circleci-2.0)

## Note

This Terraform provider is a fork of [a previous implementation by Pryz](https://github.com/Pryz/terraform-provider-ldap), which is still available.
This fork is actively maintained.

*Last updated: 2019-02-05*

## How to build and install

### Build

In order to build this plugin, you need to have a working setup of Golang; you can find detailed instructions on [Golang's website](https://golang.org/doc/install).

This project does not use Golang modules (`go mod`) yet, so you need to manually get the plugin sources (along with those of Terraform and the LDAP client) like this: 

```bash
$> go get -d -u github.com/dihedron/terraform-provider-ldap
$> go get -d -u github.com/hashicorp/terraform
$> go get -d -u gopkg.in/ldap.v2
```
Open a command prompt and run:
```bash
$> go build github.com/dihedron/terraform-provider-ldap
```
The newly build binary will be in the current directory.

### Installation

Terraform can "sideload" custom plugins; you only need to place the binary that was produced in the build step under the plugins directory:

| Platform         |        Directory                |
|:-----------------|---------------------------------|
|Windows           |%APPDATA%\terraform.d\plugins    |
|All other systems |~/.terraform.d/plugins           |

You can find detailed instruction on [Hashicorp's website](https://www.terraform.io/docs/configuration/providers.html#third-party-plugins).


## Provider example

```
provider "ldap" {
    ldap_host = "ldap.example.org"
    ldap_port = 389
    use_tls = false
    bind_user = "cn=admin,dc=example,dc=com"
    bind_password = "admin"
}
```
Note: if you want to use TLS, the LDAP port must be changed accordingly 
(typically, port 636 is used for secure connections).

## Resource LDAP Object example

```
resource "ldap_object" "foo" {
    # DN must be complete (no RDN!)
    dn = "uid=foo,dc=example,dc=com"

    # classes are specified as an array
    object_classes = [
        "inetOrgPerson",
        "posixAccount",
    ]

    # attributes are specified as a set of 1-element maps
    attributes = [
        { sn              = "10" },
        { cn              = "bar" },
        { uidNumber       = "1234" },
        { gidNumber       = "1234" },
        { homeDirectory   = "/home/billy" },
        { loginShell      = "/bin/bash" },
        # when an attribute has multiple values, it must be specified multiple times
        { mail            = "billy@example.com" },
        { mail            = "admin@example.com" },
    ]
}
```

The Bind User must have write access for resource creation to succeed.

## Features

This provider is feature complete.

As of the latest release, it supports resource creation, reading, update, deletion and importing.

It can be used to create nested resources at all levels of the hierarchy, provided the proper (implicit or explicit) dependencies are declared.

When updating an object, the plugin computes the minimum set of attributes that need to be added, modified and removed and surgically operates on the remote object to bring it up to date.

When importing existing LDAP objects into the Terraform state, the plugin can automatically generate a .tf file with the relevant information, so the next `terraform apply` does not drop the imported resource from the remote LDAP server because it cannot find it in the local `.tf` files.

In order to let the plugin generate this file, put the name of the output file (which must *not* exist on disk) in the `TF_LDAP_IMPORTER_PATH` environment variable, like this:

```bash
$> export TF_LDAP_IMPORTER_PATH=my_ldap_dump.tf 
$> terraform import ldap_object.a123456 uid=a123456,ou=users,dc=example,dc=com
```

and the plugin will create the `my_ldap_dump.tf` file with the proper information.

Then merge this file with your existing `.tf` file(s).

## Limitations

This provider supports TLS, but certificate verification is not enabled yet; all connections are through TCP, no UDP support yet.