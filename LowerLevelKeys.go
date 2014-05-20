package main

/*************************************************************************
// Lower-Level Keys
//
//Keys that are used lower in the hierarchy of the pass.json file—for example, in a dictionary that is the value of a top-level key.
//https://developer.apple.com/library/ios/documentation/userexperience/Reference/PassKit_Bundle/Chapters/LowerLevel.html#//apple_ref/doc/uid/TP40012026-CH3-SW1
************************************************************************/

//////////////////////////////////////////////////////////////////////////
// Pass Structure Dictionary Keys
//
// Keys that define the structure of the pass.
// These keys are used for all pass styles and partition the fields into the various parts of the pass.
//////////////////////////////////////////////////////////////////////////
type passStructure struct {
	AuxiliaryFields []fields `json:"auxiliaryFields,omitempty" gorethink:"auxiliaryFields,omitempty"` //Optional. Additional fields to be displayed on the front of the pass.
	BackFields      []fields `json:"backFields,omitempty" gorethink:"backFields,omitempty"`           //Optional. Fields to be on the back of the pass.
	HeaderFields    []fields `json:"headerFields,omitempty" gorethink:"headerFields,omitempty"`       //Optional. Fields to be displayed in the header on the front of the pass, they remain visible when a stack of passes are displayed.
	PrimaryFields   []fields `json:"primaryFields,omitempty" gorethink:"primaryFields,omitempty"`     //Optional. Fields to be displayed prominently on the front of the pass.
	SecondaryFields []fields `json:"secondaryFields,omitempty" gorethink:"secondaryFields,omitempty"` //Optional. Fields to be displayed on the front of the pass.
	TransitType     string   `json:"transitType,omitempty" gorethink:"transitType,omitempty"`         //Required for boarding passes; otherwise not allowed. Type of transit.
}

//////////////////////////////////////////////////////////////////////////
// Beacon Dictionary Keys
//
// Information about a location beacon.
//////////////////////////////////////////////////////////////////////////
type beacon struct {
	Major         int    `json:"major,omitempty" gorethink:"major,omitempty"`               //Optional. Major identifier of a Bluetooth Low Energy location beacon.
	Minor         int    `json:"minor,omitempty" gorethink:"minor,omitempty"`               //Optional. Minor identifier of a Bluetooth Low Energy location beacon.
	ProximityUUID string `json:"proximityUUID" gorethink:"proximityUUID"`                   //Required. Unique identifier of a Bluetooth Low Energy location beacon.
	RelevantText  string `json:"relevantText,omitempty" gorethink:"relevantText,omitempty"` //Optional. Text displayed on the lock screen when the pass is currently relevant.
}

//////////////////////////////////////////////////////////////////////////
// Location Dictionary Keys
//
// Information about a location.
//////////////////////////////////////////////////////////////////////////
type location struct {
	Altitude     float64 `json:"altitude,omitempty" gorethink:"altitude,omitempty"`         //Optional. Altitude, in meters, of the location.
	Latitude     float64 `json:"latitude" gorethink:"latitude"`                             //Required. Latitude, in degrees, of the location.
	Longitude    float64 `json:"longitude" gorethink:"longitude"`                           //Required. Longitude, in degrees, of the location.
	RelevantText string  `json:"relevantText,omitempty" gorethink:"relevantText,omitempty"` //Optional. Text displayed on the lock screen when the pass is currently relevant.
}

//////////////////////////////////////////////////////////////////////////
// Barcode Dictionary Keys
//
// Information about a pass’s barcode.
//////////////////////////////////////////////////////////////////////////
type barcode struct {
	AltText         string `json:"altText,omitempty" gorethink:"altText,omitempty"` //Optional. Text displayed near the barcode, a human-readable version of the barcode data in case the barcode doesn’t scan.
	Format          string `json:"format" gorethink:"format"`                       //Required. Barcode format. Must be one of the following values: PKBarcodeFormatQR, PKBarcodeFormatPDF417, PKBarcodeFormatAztec.
	Message         string `json:"message" gorethink:"message"`                     //Required. Message or payload to be displayed as a barcode.
	MessageEncoding string `json:"messageEncoding" gorethink:"messageEncoding"`     //Required. Text encoding that is used to convert the message from the string representation to a data representation to render the barcode. eg: iso-8859-1
}

/*************************************************************************
Field Dictionary Keys

Keys that are used at the lowest level of the pass.json file, which define an individual field.
************************************************************************/

type fields struct {
	AttributedValue   string   `json:"attributedValue,omitempty" gorethink:"attributedValue,omitempty"`     //Optional. Attributed value of the field. The value may contain HTML markup for links. Only the <a> tag and its href attribute are supported.
	ChangeMessage     string   `json:"changeMessage,omitempty" gorethink:"changeMessage,omitempty"`         //Optional. Format string for the alert text that is displayed when the pass is updated.
	DataDetectorTypes []string `json:"dataDetectorTypes,omitempty" gorethink:"dataDetectorTypes,omitempty"` //Optional. Data dectors that are applied to the field’s value.
	Key               string   `json:"key" gorethink:"key"`                                                 //Required. The key must be unique within the scope of the entire pass. For example, “departure-gate”.
	Label             string   `json:"label,omitempty" gorethink:"label,omitempty"`                         //Optional. Label text for the field.
	TextAlignment     string   `json:"textAlignment,omitempty" gorethink:"textAlignment,omitempty"`         //Optional. Alignment for the field’s contents
	Value             string   `json:"value" gorethink:"value"`                                             //Required. Value of the field. For example, 42

	DateStyle       string `json:"dateStyle,omitempty" gorethink:"dateStyle,omitempty"`             //Style of date to display
	IgnoresTimeZone bool   `json:"ignoresTimeZone,omitempty" gorethink:"ignoresTimeZone,omitempty"` //Optional. Always display the time and date in the given time zone, not in the user’s current time zone. The default value is false.
	IsRelative      bool   `json:"isRelative,omitempty" gorethink:"isRelative,omitempty"`           //Optional. If true, the label’s value is displayed as a relative date; otherwise, it is displayed as an absolute date.
	TimeStyle       string `json:"timeStyle,omitempty" gorethink:"timeStyle,omitempty"`             //Style of time to display.

	CurrencyCode string `json:"currencyCode,omitempty" gorethink:"currencyCode,omitempty"` //ISO 4217 currency code for the field’s value.
	NumberStyle  string `json:"numberStyle,omitempty" gorethink:"numberStyle,omitempty"`   //Style of number to display.
}
