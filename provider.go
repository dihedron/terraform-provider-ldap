// Copyright 2018-present Andrea Funtò. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"sync"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	ldap "gopkg.in/ldap.v2"
)

// DescribeLDAPProvider describes an LDAP provider in terms of Terraform internal
// structures.
func DescribeLDAPProvider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"ldap_host": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_HOST", nil),
				Description: "The LDAP server to connect to.",
			},
			"ldap_port": &schema.Schema{
				Type:        schema.TypeInt,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_PORT", 389),
				Description: "The LDAP protocol port (default: 389).",
			},
			"use_tls": &schema.Schema{
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_USE_TLS", true),
				Description: "Use TLS to secure the connection (default: true).",
			},
			"bind_user": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_BIND_USER", nil),
				Description: "Bind user to be used for authenticating on the LDAP server.",
			},
			"bind_password": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("LDAP_BIND_PASSWORD", nil),
				Description: "Password to authenticate the Bind user.",
			},
		},

		ConfigureFunc: func(d *schema.ResourceData) (interface{}, error) {
			return &LDAPProvider{
				Host:         d.Get("ldap_host").(string),
				Port:         d.Get("ldap_port").(int),
				UseTLS:       d.Get("use_tls").(bool),
				BindUser:     d.Get("bind_user").(string),
				BindPassword: d.Get("bind_password").(string),
			}, nil
		},

		ResourcesMap: map[string]*schema.Resource{
			"ldap_object": DescribeLDAPObject(),
		},
	}
}

// binding is the struct holding information about the bound connection to an
// LDAP provider (server).
type binding struct {
	connection *ldap.Conn
	err        error
}

// cache is the lazily initialized connection, returned from the first Bind call.
var cache *binding

// once guards the binding logic against concurrent and reiterated invocations.
var once sync.Once

// LDAPProvider is the set of parameters needed to configure the LDAP provider.
type LDAPProvider struct {
	Host         string
	Port         int
	UseTLS       bool
	BindUser     string
	BindPassword string
}

// Bind when invoked the very first time, uses the binding information stored
// in the LDAPProvider object to connect and bind to an LDAP server, then caches
// that information in a global cache variable that is subsequently used to return
// the bound connection. The usage of once.Do ensures that the connection and
// binding is only performed once; concurrent calls are blocked and subsequent
// calls skip the invocation of the actual binding logic altogether.
func (p *LDAPProvider) Bind() (*ldap.Conn, error) {

	// do it only the first time; subsequent calls will not cause the anonymous
	// function to be invoked, and the cached result will be returned instead;
	// the anonymous function will populate the cached binding for usage by
	// subsequent calls
	once.Do(func() {
		cache = &binding{}

		log.Printf("[INFO] Bind - Dialing server %q on port %d", p.Host, p.Port)

		// TODO: should we handle UDP, which seems to be predominantly used by
		// Microsoft AD and little, if none, others?
		connection, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", p.Host, p.Port))
		if err != nil {
			log.Printf("[ERROR] Bind - error dialing server: %v", err)
			cache.err = err
			return
		}

		// handle TLS
		if p.UseTLS {
			//TODO: Finish the TLS integration by using trust anchors
			err = connection.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				log.Printf("[ERROR] Bind - error starting TLS on connection: %v", err)
				connection.Close()
				cache.err = err
				return
			}
		}

		log.Printf("[DEBUG] Bind - connected to server %q on port %d", p.Host, p.Port)

		// use connection to bind user
		err = connection.Bind(p.BindUser, p.BindPassword)
		if err != nil {
			log.Printf("[ERROR] Bind - error binding user %q: %v", p.BindUser, err)
			connection.Close()
			cache.err = err
		}

		log.Printf("[INFO] Bind - bound to server %q on port %d using %q", p.Host, p.Port, p.BindUser)

		// store the LDAP connection into cache
		cache.connection = connection
	})

	// return the cached binding connection and error
	log.Printf("[DEBUG] Bind - returning cached connection (error: %v)", cache.err)
	return cache.connection, cache.err
}
