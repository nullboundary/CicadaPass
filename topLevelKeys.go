package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"
)

const (
	EnterprisePlan = 0     //Unlimited
	FreePlan       = 5     //Five preview downloads
	SmallPlan      = 10000 //10,000 downloads per type
)

//userModel struct represents a user in the system
type userModel struct {
	ID    string `gorethink:"id"`
	Email string `gorethink:"email"` //Email is ID of user
	//User          goth.User `gorethink:"user"`                   //Detailed User info from oauth login
	Organization  string    `gorethink:"organization,omitempty"` //User organization name
	OAuthProvider string    `gorethink:"oauth"`                  //User is using OAuth login, not email
	Created       time.Time `gorethink:"created,omitempty"`      //Account Created time/date
	LastLogin     time.Time `gorethink:"lastLogin,omitempty"`    //Last login time
	Subscriber    bool      `gorethink:"subscriber,omitempty"`   //subscriber: true or false? (false could be free trial users)
	SubStart      time.Time `gorethink:"subStart,omitempty"`     //Subscription start date
	SubExpiration time.Time `gorethink:"subExpire,omitempty"`    //Subscription expiration date
	SubPlan       int       `gorethink:"subPlan,omitempty"`      //Subscription plan for this user
	PassList      []string  `gorethink:"passList,omitempty"`     //A list of the pass Ids this users has made
}

type registerPass struct {
	PassTypeId   string    `json:"id" gorethink:"id" valid:"required"`    //Pass type ID
	SerialNumber string    `json:"serialNumber" gorethink:"serialNumber"` //Serial number that uniquely identifies the pass.
	Updated      time.Time `json:"updated" gorethink:"updated"`           //when the pass was last updated or created
}

type device struct {
	DeviceLibId string         `json:"deviceLibId" gorethink:"deviceLibId"` //The device library identifier is a Passbook-specific shared secret between the user’s device and your web server.
	PushToken   string         `json:"pushToken" gorethink:"pushToken"`     //An APN Push token
	PassList    []registerPass `json:"passList" gorethink:"passList"`       //a list of passes that this device has
}

type pass struct {
	Id          string            `json:"id" gorethink:"id" valid:"required"`                                    //Pass ID - used for updating, but not sharing
	Name        string            `json:"name" gorethink:"name" valid:"required"`                                //Pass name for user identification
	FileName    string            `json:"filename,omitempty" gorethink:"filename,omitempty"`                     //A generated filename for the pass for downloading and sharing
	UserId      string            `json:"-" gorethink:"userid,omitempty"`                                        //The Id of the pass creator
	PassType    string            `json:"passtype,omitempty" gorethink:"passtype,omitempty" valid:"passtypes"`   //The pass type, boardingpass, coupon, etc.
	KeyDoc      *passKeys         `json:"keyDoc,omitempty" gorethink:"keyDoc,omitempty"`                         //The pass.json file, all the structs used to create it
	Images      []passImage       `json:"images,omitempty" gorethink:"images,omitempty"`                         //All the images needed for a pass
	ManifestDoc map[string]string `json:"manifest,omitempty" gorethink:"manifest,omitempty"`                     //The manifest.json file, used to verify the content of a pass
	Updated     time.Time         `json:"updated" gorethink:"updated" valid:"required"`                          //when the pass was last updated or created
	Status      string            `json:"status" gorethink:"status" valid:"required"`                            //Is the pass ready for distribution, in process, or expired
	CertId      string            `json:"cert,omitempty" gorethink:"cert,omitempty"`                             //Id to the certificate used to sign the pass
	MutateList  []string          `json:"mutatelist,omitempty" gorethink:"mutatelist,omitempty"`                 //List of value keys used to change the pass via the api upon issuing
	PassRemain  int               `json:"passremain,omitempty" gorethink:"passremain,omitempty" valid:"numeric"` //count down from plan max number of downloaded passes of this template
}

/*************************************************************************
//Image Files


************************************************************************/
type passImage struct {
	ImageData string `json:"image,omitempty" gorethink:"image,omitempty" valid:"imagepng"`
	ImageName string `json:"name,omitempty" gorethink:"name,omitempty"`
}

/*************************************************************************
//Top-Level Keys

//The top level of the pass.json file is a dictionary. The following sections list the required and optional keys used in this dictionary.
//For each key whose value is a dictionary or an array of dictionaries, there is also a section in “Lower-Level Keys” that lists the keys for that dictionary.

//https://developer.apple.com/library/ios/documentation/userexperience/Reference/PassKit_Bundle/Chapters/TopLevel.html#//apple_ref/doc/uid/TP40012026-CH2-SW1
************************************************************************/

//////////////////////////////////////////////////////////////////////////
// Standard Keys
//
// Information that is required for all passes.
//////////////////////////////////////////////////////////////////////////
type passKeys struct {
	Description        string `json:"description,omitempty" gorethink:"description,omitempty"`               //Brief description of the pass, used by the iOS accessibility technologies.
	FormatVersion      int    `json:"formatVersion,omitempty" gorethink:"formatVersion,omitempty"`           //Version of the file format. The value must be 1.
	OrganizationName   string `json:"organizationName,omitempty" gorethink:"organizationName,omitempty"`     //Display name of the organization that originated and signed the pass.
	PassTypeIdentifier string `json:"passTypeIdentifier,omitempty" gorethink:"passTypeIdentifier,omitempty"` //Pass type identifier, as issued by Apple. The value must correspond with your signing certificate.
	SerialNumber       string `json:"serialNumber,omitempty" gorethink:"serialNumber,omitempty"`             //Serial number that uniquely identifies the pass. No two passes with the same pass type identifier may have the same serial number.
	TeamIdentifier     string `json:"teamIdentifier,omitempty" gorethink:"teamIdentifier,omitempty"`         //Team identifier of the organization that originated and signed the pass, as issued by Apple

	//////////////////////////////////////////////////////////////////////////
	// Associated App Keys
	//
	// Information about an app that is associated with a pass.
	//////////////////////////////////////////////////////////////////////////

	AppLaunchURL               string `json:"appLaunchURL,omitempty" gorethink:"appLaunchURL,omitempty" valid:"url"`                 //Optional. A URL to be passed to the associated app when launching it.
	AssociatedStoreIdentifiers []int  `json:"associatedStoreIdentifiers,omitempty" gorethink:"associatedStoreIdentifiers,omitempty"` //Optional. A list of iTunes Store item identifiers for the associated apps.

	//////////////////////////////////////////////////////////////////////////
	// Companion App Keys
	//
	//Custom information about a pass provided for a companion app to use.
	//////////////////////////////////////////////////////////////////////////

	UserInfo json.RawMessage `json:"userInfo,omitempty" gorethink:"userInfo,omitempty"` //Optional. Custom information for companion apps. This data is not displayed to the user.

	//////////////////////////////////////////////////////////////////////////
	// Expiration Keys
	//
	// Information about when a pass expires and whether it is still valid.
	// A pass is marked as expired if the current date is after the pass’s expiration date, or if the pass has been explicitly marked as voided.
	//////////////////////////////////////////////////////////////////////////

	ExpirationDate *Time `json:"expirationDate,omitempty" gorethink:"expirationDate,omitempty"` //Optional. Date and time when the pass expires.
	Voided         bool  `json:"voided,omitempty" gorethink:"voided,omitempty"`                 //Optional. Indicates that the pass is void—for example, a one time use coupon that has been redeemed.

	//////////////////////////////////////////////////////////////////////////
	// Relevance Keys
	//
	// Information about where and when a pass is relevant.
	//////////////////////////////////////////////////////////////////////////

	Beacons      []beacon   `json:"beacons,omitempty" gorethink:"beacons,omitempty"`                     //Optional. Beacons marking locations where the pass is relevant.
	Locations    []location `json:"locations,omitempty" gorethink:"locations,omitempty"`                 //Optional. Locations where the pass is relevant. For example, the location of your store.
	MaxDistance  int        `json:"maxDistance,omitempty" gorethink:"maxDistance,omitempty" valid:"int"` //Optional. Maximum distance in meters from a relevant latitude and longitude that the pass is relevant.
	RelevantDate *Time      `json:"relevantDate,omitempty" gorethink:"relevantDate,omitempty"`           //Optional. Date and time when the pass becomes relevant. For example, the start time of a movie.

	//////////////////////////////////////////////////////////////////////////
	// Style Keys
	//
	// Specifies the pass style.
	//Provide exactly one key—the key that corresponds with the pass’s type. The value of this key is a dictionary containing the keys in “Pass Structure Dictionary Keys.”
	//////////////////////////////////////////////////////////////////////////

	BoardingPass *passStructure `json:"boardingPass,omitempty" gorethink:"boardingPass,omitempty"` //Information specific to a boarding pass
	Coupon       *passStructure `json:"coupon,omitempty" gorethink:"coupon,omitempty"`             //Information specific to a coupon.
	EventTicket  *passStructure `json:"eventTicket,omitempty" gorethink:"eventTicket,omitempty"`
	Generic      *passStructure `json:"generic,omitempty" gorethink:"generic,omitempty"`
	StoreCard    *passStructure `json:"storeCard,omitempty" gorethink:"storeCard,omitempty"`

	//////////////////////////////////////////////////////////////////////////
	// Visual Appearance Keys
	//
	// Visual styling and appearance of the pass.
	//////////////////////////////////////////////////////////////////////////

	Barcode            *barcode `json:"barcode,omitempty" gorethink:"barcode,omitempty"`                                  //Optional. Information specific to barcodes
	BackgroundColor    string   `json:"backgroundColor,omitempty" gorethink:"backgroundColor,omitempty" valid:"rgbcolor"` //Optional. Background color of the pass, specified as an CSS-style RGB triple. For example, rgb(23, 187, 82).
	ForegroundColor    string   `json:"foregroundColor,omitempty" gorethink:"foregroundColor,omitempty" valid:"rgbcolor"` //Optional. Foreground color of the pass, specified as a CSS-style RGB triple.
	GroupingIdentifier string   `json:"groupingIdentifier,omitempty" gorethink:"groupingIdentifier,omitempty"`            //Optional. Use this to group passes that are tightly related, such as the boarding passes for different connections of the same trip.
	LabelColor         string   `json:"labelColor,omitempty" gorethink:"labelColor,omitempty" valid:"rgbcolor"`           //Optional. Color of the label text, specified as a CSS-style RGB triple.
	LogoText           string   `json:"logoText,omitempty" gorethink:"logoText,omitempty"`                                //Optional. Text displayed next to the logo on the pass.
	SuppressStripShine bool     `json:"suppressStripShine,omitempty" gorethink:"suppressStripShine,omitempty"`            //Optional. If true, the strip image is displayed without a shine effect.

	//////////////////////////////////////////////////////////////////////////
	// Web Service Keys
	//
	// Information used to update passes using the web service.
	// If a web service URL is provided, an authentication token is required; otherwise, these keys are not allowed.
	//////////////////////////////////////////////////////////////////////////

	AuthenticationToken string `json:"authenticationToken,omitempty" gorethink:"authenticationToken,omitempty"`    //The authentication token to use with the web service. The token must be 16 characters or longer.
	WebServiceURL       string `json:"webServiceURL,omitempty" gorethink:"webServiceURL,omitempty" valid:"requrl"` //The URL of a web service
}

//////////////////////////////////////////////////////////////////////////
//
//	newPass returns a pointer to a pass.
//
//
//////////////////////////////////////////////////////////////////////////
func newPass() *pass {
	return &pass{}
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func (p *pass) getPassStructure() (*passStructure, error) {

	//get the correct pass type keyDoc
	var keyDocType *passStructure
	switch p.PassType {
	case "boardingPass":
		keyDocType = p.KeyDoc.BoardingPass
	case "coupon":
		keyDocType = p.KeyDoc.Coupon
	case "eventTicket":
		keyDocType = p.KeyDoc.EventTicket
	case "generic":
		keyDocType = p.KeyDoc.Generic
	case "storeCard":
		keyDocType = p.KeyDoc.StoreCard
	default:
		log.Printf("[WARN] Pass type %s not found", p.PassType)
		return keyDocType, fmt.Errorf("the submitted pass type is malformed")
	}
	return keyDocType, nil
}

//////////////////////////////////////////////////////////////////////////
//
//	setPassTypeIdentifier sets the passtype identifier in the keydoc to match the certificate.
//	TODO: this solution won't work if we implement user generated certs in the future!
//
//////////////////////////////////////////////////////////////////////////
func (p *pass) setPassTypeIdentifier() error {

	//get the correct pass type id
	switch p.PassType {
	case "boardingPass":
		p.KeyDoc.PassTypeIdentifier = "pass.ninja.pass.boardingpass"
	case "coupon":
		p.KeyDoc.PassTypeIdentifier = "pass.ninja.pass.coupon"
	case "eventTicket":
		p.KeyDoc.PassTypeIdentifier = "pass.ninja.pass.eventticket"
	case "generic":
		p.KeyDoc.PassTypeIdentifier = "pass.ninja.pass.generic"
	case "storeCard":
		p.KeyDoc.PassTypeIdentifier = "pass.ninja.pass.storecard"
	default:
		log.Printf("[WARN] Pass type %s not found", p.PassType)
		return fmt.Errorf("the submitted data is malformed")
	}

	return nil
}
