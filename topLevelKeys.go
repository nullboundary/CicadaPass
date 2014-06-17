package main

import (
	"time"
)

type registerPass struct {
	PassTypeId   string    `json:"id" gorethink:"id"`                     //Pass type ID
	SerialNumber string    `json:"serialNumber" gorethink:"serialNumber"` //Serial number that uniquely identifies the pass.
	Updated      time.Time `json:"updated" gorethink:"updated"`           //when the pass was last updated or created
}

type device struct {
	DeviceLibId string         `json:"deviceLibId" gorethink:"deviceLibId"` //The device library identifier is a Passbook-specific shared secret between the user’s device and your web server.
	PushToken   string         `json:"pushToken" gorethink:"pushToken"`     //An APN Push token
	PassList    []registerPass `json:"passList" gorethink:"passList"`       //a list of passes that this device has
}

type pass struct {
	Id          string            `json:"id" gorethink:"id"`             //Pass type ID
	KeyDoc      passKeys          `json:"keyDoc" gorethink:"keyDoc"`     //The pass.json file, all the structs used to create it
	Images      []passImage       `json:"images" gorethink:"images"`     //All the images needed for a pass
	ManifestDoc map[string]string `json:"manifest" gorethink:"manifest"` //The manifest.json file, used to verify the content of a pass
	Updated     time.Time         `json:"updated" gorethink:"updated"`   //when the pass was last updated or created
}

/*************************************************************************
//Image Files


************************************************************************/
type passImage struct {
	ImageData string `json:"image,omitempty" gorethink:"image,omitempty"`
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
	Description        string `json:"description" gorethink:"description"`               //Brief description of the pass, used by the iOS accessibility technologies.
	FormatVersion      int    `json:"formatVersion" gorethink:"formatVersion"`           //Version of the file format. The value must be 1.
	OrganizationName   string `json:"organizationName" gorethink:"organizationName"`     //Display name of the organization that originated and signed the pass.
	PassTypeIdentifier string `json:"passTypeIdentifier" gorethink:"passTypeIdentifier"` //Pass type identifier, as issued by Apple. The value must correspond with your signing certificate.
	SerialNumber       string `json:"serialNumber" gorethink:"serialNumber"`             //Serial number that uniquely identifies the pass. No two passes with the same pass type identifier may have the same serial number.
	TeamIdentifier     string `json:"teamIdentifier" gorethink:"teamIdentifier"`         //Team identifier of the organization that originated and signed the pass, as issued by Apple

	//////////////////////////////////////////////////////////////////////////
	// Associated App Keys
	//
	// Information about an app that is associated with a pass.
	//////////////////////////////////////////////////////////////////////////

	AppLaunchURL               string `json:"appLaunchURL,omitempty" gorethink:"appLaunchURL,omitempty"`                             //Optional. A URL to be passed to the associated app when launching it.
	AssociatedStoreIdentifiers []int  `json:"associatedStoreIdentifiers,omitempty" gorethink:"associatedStoreIdentifiers,omitempty"` //Optional. A list of iTunes Store item identifiers for the associated apps.

	//////////////////////////////////////////////////////////////////////////
	// Companion App Keys
	//
	//Custom information about a pass provided for a companion app to use.
	//////////////////////////////////////////////////////////////////////////

	UserInfo map[string]string `json:"userInfo,omitempty" gorethink:"userInfo,omitempty"` //Optional. Custom information for companion apps. This data is not displayed to the user.

	//////////////////////////////////////////////////////////////////////////
	// Expiration Keys
	//
	// Information about when a pass expires and whether it is still valid.
	// A pass is marked as expired if the current date is after the pass’s expiration date, or if the pass has been explicitly marked as voided.
	//////////////////////////////////////////////////////////////////////////

	ExpirationDate time.Time `json:"expirationDate,omitempty" gorethink:"expirationDate,omitempty"` //Optional. Date and time when the pass expires.
	Voided         bool      `json:"voided,omitempty" gorethink:"voided,omitempty"`                 //Optional. Indicates that the pass is void—for example, a one time use coupon that has been redeemed.

	//////////////////////////////////////////////////////////////////////////
	// Relevance Keys
	//
	// Information about where and when a pass is relevant.
	//////////////////////////////////////////////////////////////////////////

	Beacons      []beacon   `json:"beacons,omitempty" gorethink:"beacons,omitempty"`           //Optional. Beacons marking locations where the pass is relevant.
	Locations    []location `json:"locations,omitempty" gorethink:"locations,omitempty"`       //Optional. Locations where the pass is relevant. For example, the location of your store.
	MaxDistance  int        `json:"maxDistance,omitempty" gorethink:"maxDistance,omitempty"`   //Optional. Maximum distance in meters from a relevant latitude and longitude that the pass is relevant.
	RelevantDate time.Time  `json:"relevantDate,omitempty" gorethink:"relevantDate,omitempty"` //Optional. Date and time when the pass becomes relevant. For example, the start time of a movie.

	//////////////////////////////////////////////////////////////////////////
	// Style Keys
	//
	// Specifies the pass style.
	//Provide exactly one key—the key that corresponds with the pass’s type. The value of this key is a dictionary containing the keys in “Pass Structure Dictionary Keys.”
	//////////////////////////////////////////////////////////////////////////

	BoardingPass passStructure `json:"boardingPass,omitempty" gorethink:"boardingPass"` //Information specific to a boarding pass
	Coupon       passStructure `json:"coupon,omitempty" gorethink:"coupon"`             //Information specific to a coupon.
	EventTicket  passStructure `json:"eventTicket,omitempty gorethink:"eventTicket"`
	Generic      passStructure `json:"generic,omitempty" gorethink:"generic"`
	StoreCard    passStructure `json:"storeCard,omitempty" gorethink:"storeCard"`

	//////////////////////////////////////////////////////////////////////////
	// Visual Appearance Keys
	//
	// Visual styling and appearance of the pass.
	//////////////////////////////////////////////////////////////////////////

	Barcode            barcode `json:"barcode,omitempty" gorethink:"barcode,omitempty"`                       //Optional. Information specific to barcodes
	BackgroundColor    string  `json:"backgroundColor,omitempty" gorethink:"backgroundColor,omitempty"`       //Optional. Background color of the pass, specified as an CSS-style RGB triple. For example, rgb(23, 187, 82).
	ForegroundColor    string  `json:"foregroundColor,omitempty" gorethink:"foregroundColor,omitempty"`       //Optional. Foreground color of the pass, specified as a CSS-style RGB triple.
	GroupingIdentifier string  `json:"groupingIdentifier,omitempty" gorethink:"groupingIdentifier,omitempty"` //Optional. Use this to group passes that are tightly related, such as the boarding passes for different connections of the same trip.
	LabelColor         string  `json:"labelColor,omitempty" gorethink:"labelColor,omitempty"`                 //Optional. Color of the label text, specified as a CSS-style RGB triple.
	LogoText           string  `json:"logoText,omitempty" gorethink:"logoText,omitempty"`                     //Optional. Text displayed next to the logo on the pass.
	SuppressStripShine bool    `json:"suppressStripShine,omitempty" gorethink:"suppressStripShine,omitempty"` //Optional. If true, the strip image is displayed without a shine effect.

	//////////////////////////////////////////////////////////////////////////
	// Web Service Keys
	//
	// Information used to update passes using the web service.
	// If a web service URL is provided, an authentication token is required; otherwise, these keys are not allowed.
	//////////////////////////////////////////////////////////////////////////

	AuthenticationToken string `json:"authenticationToken,omitempty" gorethink:"authenticationToken,omitempty"` //The authentication token to use with the web service. The token must be 16 characters or longer.
	WebServiceURL       string `json:"webServiceURL,omitempty" gorethink:"webServiceURL,omitempty"`             //The URL of a web service
}
