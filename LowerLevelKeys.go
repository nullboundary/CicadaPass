package main

import (
	"bitbucket.org/cicadaDev/storer"
	"encoding/json"
	"fmt"
	"github.com/dancannon/gorethink/encoding"
	"log"
	"reflect"
	"strconv"
	"time"
)

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
	AuxiliaryFields []fields `json:"auxiliaryFields,omitempty" gorethink:"auxiliaryFields,omitempty"`         //Optional. Additional fields to be displayed on the front of the pass.
	BackFields      []fields `json:"backFields,omitempty" gorethink:"backFields,omitempty"`                   //Optional. Fields to be on the back of the pass.
	HeaderFields    []fields `json:"headerFields,omitempty" gorethink:"headerFields,omitempty"`               //Optional. Fields to be displayed in the header on the front of the pass, they remain visible when a stack of passes are displayed.
	PrimaryFields   []fields `json:"primaryFields,omitempty" gorethink:"primaryFields,omitempty"`             //Optional. Fields to be displayed prominently on the front of the pass.
	SecondaryFields []fields `json:"secondaryFields,omitempty" gorethink:"secondaryFields,omitempty"`         //Optional. Fields to be displayed on the front of the pass.
	TransitType     string   `json:"transitType,omitempty" gorethink:"transitType,omitempty" valid:"transit"` //Required for boarding passes; otherwise not allowed. Type of transit.
}

//////////////////////////////////////////////////////////////////////////
// Beacon Dictionary Keys
//
// Information about a location beacon.
//////////////////////////////////////////////////////////////////////////
type beacon struct {
	Major         int    `json:"major,omitempty" gorethink:"major,omitempty" valid:"int"`                  //Optional. Major identifier of a Bluetooth Low Energy location beacon.
	Minor         int    `json:"minor,omitempty" gorethink:"minor,omitempty" valid:"int"`                  //Optional. Minor identifier of a Bluetooth Low Energy location beacon.
	ProximityUUID string `json:"proximityUUID,omitempty" gorethink:"proximityUUID,omitempty" valid:"uuid"` //Required. Unique identifier of a Bluetooth Low Energy location beacon.
	RelevantText  string `json:"relevantText,omitempty" gorethink:"relevantText,omitempty"`                //Optional. Text displayed on the lock screen when the pass is currently relevant.
}

//////////////////////////////////////////////////////////////////////////
// Location Dictionary Keys
//
// Information about a location.
//////////////////////////////////////////////////////////////////////////
type location struct {
	Altitude     float64 `json:"altitude,omitempty" gorethink:"altitude,omitempty"`                     //Optional. Altitude, in meters, of the location.
	Latitude     float64 `json:"latitude,omitempty" gorethink:"latitude,omitempty" valid:"latitude"`    //Required. Latitude, in degrees, of the location.
	Longitude    float64 `json:"longitude,omitempty" gorethink:"longitude,omitempty" valid:"longitude"` //Required. Longitude, in degrees, of the location.
	RelevantText string  `json:"relevantText,omitempty" gorethink:"relevantText,omitempty"`             //Optional. Text displayed on the lock screen when the pass is currently relevant.
}

//////////////////////////////////////////////////////////////////////////
// Barcode Dictionary Keys
//
// Information about a pass’s barcode.
//////////////////////////////////////////////////////////////////////////
type barcode struct {
	AltText         string `json:"altText,omitempty" gorethink:"altText,omitempty"`                 //Optional. Text displayed near the barcode, a human-readable version of the barcode data in case the barcode doesn’t scan.
	Format          string `json:"format,omitempty" gorethink:"format,omitempty" valid:"barcode"`   //Required. Barcode format. Must be one of the following values: PKBarcodeFormatQR, PKBarcodeFormatPDF417, PKBarcodeFormatAztec.
	Message         string `json:"message,omitempty" gorethink:"message,omitempty"`                 //Required. Message or payload to be displayed as a barcode.
	MessageEncoding string `json:"messageEncoding,omitempty" gorethink:"messageEncoding,omitempty"` //Required. Text encoding that is used to convert the message from the string representation to a data representation to render the barcode. eg: iso-8859-1
}

/*************************************************************************
Field Dictionary Keys

Keys that are used at the lowest level of the pass.json file, which define an individual field.
************************************************************************/

type fields struct {
	AttributedValue   string   `json:"attributedValue,omitempty" gorethink:"attributedValue,omitempty"`           //Optional. Attributed value of the field. The value may contain HTML markup for links. Only the <a> tag and its href attribute are supported.
	ChangeMessage     string   `json:"changeMessage,omitempty" gorethink:"changeMessage,omitempty"`               //Optional. Format string for the alert text that is displayed when the pass is updated.
	DataDetectorTypes []string `json:"dataDetectorTypes,omitempty" gorethink:"dataDetectorTypes,omitempty"`       //Optional. Data dectors that are applied to the field’s value.
	Key               string   `json:"key,omitempty" gorethink:"key,omitempty"`                                   //Required. The key must be unique within the scope of the entire pass. For example, “departure-gate”.
	Label             string   `json:"label,omitempty" gorethink:"label,omitempty"`                               //Optional. Label text for the field.
	TextAlignment     string   `json:"textAlignment,omitempty" gorethink:"textAlignment,omitempty" valid:"align"` //Optional. Alignment for the field’s contents
	Value             *value   `json:"value" gorethink:"value"`                                                   //Required. Value of the field. For example, 42

	DateStyle       string `json:"dateStyle,omitempty" gorethink:"dateStyle,omitempty" valid:"datestyle"` //Style of date to display
	IgnoresTimeZone bool   `json:"ignoresTimeZone,omitempty" gorethink:"ignoresTimeZone,omitempty"`       //Optional. Always display the time and date in the given time zone, not in the user’s current time zone. The default value is false.
	IsRelative      bool   `json:"isRelative,omitempty" gorethink:"isRelative,omitempty"`                 //Optional. If true, the label’s value is displayed as a relative date; otherwise, it is displayed as an absolute date.
	TimeStyle       string `json:"timeStyle,omitempty" gorethink:"timeStyle,omitempty" valid:"datestyle"` //Style of time to display.

	CurrencyCode string `json:"currencyCode,omitempty" gorethink:"currencyCode,omitempty" valid:"iso4217"` //ISO 4217 currency code for the field’s value.
	NumberStyle  string `json:"numberStyle,omitempty" gorethink:"numberStyle,omitempty" valid:"numstyle"`  //Style of number to display.
}

/*************************************************************************
Value type

Used with json.Unmarshal interface to assign either string, float or int to value
************************************************************************/
type value struct {
	ValueInt    int64   `json:"valueint,omitempty" gorethink:"valueint,omitempty"`
	ValueFloat  float64 `json:"valuefloat,omitempty" gorethink:"valuefloat,omitempty"`
	ValueString string  `json:"valuestring,omitempty" gorethink:"valuestring,omitempty"`
}

/*************************************************************************
Time type

marshals and unmarshals more flexibly into json and RQL (rethinkdb)
************************************************************************/
type Time time.Time

/*************************************************************************

	Data marshalers for custom data types

************************************************************************/

//////////////////////////////////////////////////////////////////////////
//
//	value type data input to the rethinkdb is marshaled into sub values of
//	int, float or string
//
//////////////////////////////////////////////////////////////////////////
func (v *value) MarshalRQL() (interface{}, error) {
	log.Printf("[DEBUG] marshalRQL")

	if v.ValueInt != int64(0) {
		return encoding.Encode(v.ValueInt)
	}
	if v.ValueFloat != float64(0) {
		return encoding.Encode(v.ValueFloat)
	}
	if v.ValueString != "" {
		return encoding.Encode(v.ValueString)
	}

	return encoding.Encode(nil)
}

//////////////////////////////////////////////////////////////////////////
//
//	value type data output from the rethinkdb is unmarshaled into a sub value of
//	int, float or string
//
//////////////////////////////////////////////////////////////////////////
func (v *value) UnmarshalRQL(b interface{}) error {

	log.Printf("[DEBUG] unmarshalRQL %+v", b)
	s := ""

	if err := encoding.Decode(&s, b); err == nil {
		log.Printf("[DEBUG] %T - %s\n", s, s)
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil { //FIXME: for "0131" creates "131"
		log.Printf("[DEBUG] %T - %d\n", n, n)
		v.ValueInt = n
		return nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		log.Printf("[DEBUG] %T - %n\n", f, f)
		v.ValueFloat = f
		return nil
	}

	v.ValueString = s

	return nil

}

var _ storer.RtValue = (*value)(nil)

//////////////////////////////////////////////////////////////////////////
//
//	Handle json unmarshalling from doc to struct of Value types for fields.
//
//
//////////////////////////////////////////////////////////////////////////
func (v *value) UnmarshalJSON(b []byte) (err error) {
	n, f, s := int64(0), float64(0), ""
	log.Printf("[DEBUG] unmarshalJSON")
	if err = json.Unmarshal(b, &s); err == nil {
		v.ValueString = s
		return
	}
	if err = json.Unmarshal(b, &f); err == nil {
		v.ValueFloat = f
		return
	}
	if err = json.Unmarshal(b, &n); err == nil {
		v.ValueInt = n

	}

	return
}

//////////////////////////////////////////////////////////////////////////
//
//	Handle json marshalling from struct to doc of Value types for fields.
//
//
//////////////////////////////////////////////////////////////////////////
func (v *value) MarshalJSON() ([]byte, error) {

	if v.ValueInt != 0 {
		return json.Marshal(v.ValueInt)
	}
	if v.ValueFloat != float64(0) {
		return json.Marshal(v.ValueFloat)
	}
	if v.ValueString != "" {
		return json.Marshal(v.ValueString)
	}
	return json.Marshal(nil)
}

//////////////////////////////////////////////////////////////////////////
//
//	Marshal into Db custom type Time by converting it to a RFC3339
//	formatted string.
//
//////////////////////////////////////////////////////////////////////////
func (t Time) MarshalRQL() (interface{}, error) {

	s := time.Time(t).Format(time.RFC3339)
	log.Printf("[DEBUG] Time MarshalRQL: %s - %v", s, t)
	return encoding.Encode(s)
}

//////////////////////////////////////////////////////////////////////////
//
//	Unmarshal from Db type time.Time or time formated string by converting
//	it to custom type Time
//
//
//////////////////////////////////////////////////////////////////////////
func (t *Time) UnmarshalRQL(b interface{}) error {
	log.Printf("[DEBUG] unmarshalRQL")
	s := ""

	//if its a time.Time return it as *Time
	v := reflect.ValueOf(b)
	if v.Type() == reflect.TypeOf(time.Time{}) {
		log.Printf("[DEBUG] %T - %v\n", b, b)
		tt := b.(time.Time)
		*t = Time(tt)
		return nil
	} else if err := encoding.Decode(&s, b); err == nil { //if string
		log.Printf("[DEBUG] %T - %s\n", s, s)
	}

	if tt, err := time.Parse(time.RFC3339, s); err == nil {
		*t = Time(tt)
		return nil
	}
	f := "2006-01-02 15:04:05 -0700"
	if tt, err := time.Parse(f, s); err == nil {
		*t = Time(tt)
		return nil
	}
	if tt, err := time.Parse(time.RubyDate, s); err == nil {
		*t = Time(tt)
	}

	return nil
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func (t Time) MarshalJSON() ([]byte, error) {
	//f := "2006-01-02 15:04:05 -0700"
	s := time.Time(t).Format(time.RFC3339)
	log.Printf("[DEBUG] Time MarshalJson: %s", s)
	return []byte(fmt.Sprintf(`"%s"`, s)), nil
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func (t *Time) UnmarshalJSON(b []byte) error {

	s := string(b)
	log.Printf("[DEBUG] UnmarshalJSON -time: %s", s)
	if tt, err := time.Parse(time.RFC3339, s); err == nil {
		*t = Time(tt)
		return nil
	}

	iso8601 := `"2006-01-02T15:04:05.000Z"`
	if tt, err := time.Parse(iso8601, s); err == nil {
		*t = Time(tt)
		return nil
	}

	f := `"2006-01-02 15:04:05 -0700"`
	if tt, err := time.Parse(f, s); err == nil {
		*t = Time(tt)
		return nil
	}
	if tt, err := time.Parse(time.RubyDate, s); err == nil {
		*t = Time(tt)
	}
	return nil

}
