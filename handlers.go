package main

import (
	"encoding/base64"
	"github.com/zenazn/goji/web"
	"log"
	"net/http"
	"time"
)

//////////////////////////////////////////////////////////////////////////
//
//	createPass Handler
//
//
//////////////////////////////////////////////////////////////////////////
func createPass(c web.C, res http.ResponseWriter, req *http.Request) {

	db, err := getDbType(c)
	if err != nil {
		log.Println(err.Error())
	}

	var newPass pass

	readJson(req, &newPass.KeyDoc) //TODO: create schema to validate data is correct

	uri, err := encodetoDataUri("icon.png", ".png")
	check(err)
	var image passImage
	image.ImageData = uri
	image.ImageName = "icon"
	newPass.Images = append(newPass.Images, image)

	//Unique PassTypeId for the db and the pass file name
	//idHash := generateFnvHashId(newPass.KeyDoc.Description, time.Now().String())  //generate a hash using pass description + time
	//newPass.KeyDoc.PassTypeIdentifier
	//companyName := strings.Replace(newPass.KeyDoc.OrganizationName, " ", "-", -1) //remove spaces from organization name
	//newPass.Id = fmt.Sprintf("%s-%d", companyName, idHash)                        //set the db id to match the file name

	newPass.Id = newPass.KeyDoc.PassTypeIdentifier //PassTypeID is same as ID in db. PassTypeID should be unique and generated in the auth tool. Should match certificate
	newPass.Updated = time.Now()                   //set updated to the created time (now)

	db.Add("pass", &newPass)

}

//////////////////////////////////////////////////////////////////////////
//
//	createPass Handler
//
//
//////////////////////////////////////////////////////////////////////////
func getByPassTypeId(c web.C, res http.ResponseWriter, req *http.Request) {

	log.Println("getByPassTypeId")

	db, err := getDbType(c)
	check(err)

	//generate a unique serial number for this pass being downloaded
	//idHash := generateFnvHashId(req.UserAgent(), time.Now().String())
	//serial := base64.URLEncoding.EncodeToString(idHash) //fmt.Sprintf("%x", idHash)
	serialHash := hashSha1Bytes([]byte(req.UserAgent() + time.Now().String()))
	serial := base64.URLEncoding.EncodeToString(serialHash)

	generatePass(c.URLParams["passTypeIdentifier"], serial, res, db)

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func registerDevicePass(c web.C, res http.ResponseWriter, req *http.Request) {
	db, err := getDbType(c)
	check(err)

	var newDevice device
	var newRegister registerPass

	//POST request to webServiceURL/version/devices/deviceLibraryIdentifier/registrations/passTypeIdentifier/serialNumber

	//1. Verify that the authentication token is correct.
	authToken := req.Header.Get("ApplePass")
	if !verifyToken(tokenPrivateKey, authToken, c.URLParams["serialNumber"], c.URLParams["passTypeIdentifier"]) {
		http.Error(res, "unauthorized", 401)
	}

	//2. Store the mapping between the device library identifier and the push token in the devices table.
	readJson(req, &newDevice)
	newDevice.DeviceLibId = c.URLParams["deviceLibraryIdentifier"]
	db.Add("clientDevices", newDevice)

	//3. Store the mapping between the pass (by pass type identifier and serial number) and the device library identifier in the registrations table
	newRegister.PassTypeId = c.URLParams["passTypeIdentifier"]
	newRegister.SerialNumber = c.URLParams["serialNumber"]
	newRegister.DeviceLibId = newDevice.DeviceLibId
	db.Add("clientRegister", newRegister)

	//TODO: If the serial number is already registered for this device, return HTTP status 200.

	//If registration succeeds, return HTTP status 201.

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func getPassSerialbyDevice(c web.C, res http.ResponseWriter, req *http.Request) {
	//GET request to webServiceURL/version/devices/deviceLibraryIdentifier/registrations/passTypeIdentifier?passesUpdatedSince=tag
	db, err := getDbType(c)
	check(err)

	var userDevice device

	dLId := c.URLParams["deviceLibraryIdentifier"]

	if !db.FindByID(dLId, userDevice) {
		http.Error(res, "device not found", 404)
		return
	}

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func getLatestByPassTypeId(c web.C, res http.ResponseWriter, req *http.Request) {
	//GET request to webServiceURL/version/passes/passTypeIdentifier/serialNumber

	//TODO: Support standard HTTP caching on this endpoint: check for the If-Modified-Since header and return HTTP status code 304 if the pass has not changed.

	db, err := getDbType(c)
	check(err)

	//1. Verify that the authentication token is correct.
	authToken := req.Header.Get("ApplePass") //is this the correct header? maybe HTTP_AUTHORIZE?
	if !verifyToken(tokenPrivateKey, authToken, c.URLParams["serialNumber"], c.URLParams["passTypeIdentifier"]) {
		http.Error(res, "unauthorized", 401)
		return
	}

	generatePass(c.URLParams["passTypeIdentifier"], c.URLParams["serialNumber"], res, db)

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func unregisterDevice(c web.C, res http.ResponseWriter, req *http.Request) {
	//DELETE request to webServiceURL/version/devices/deviceLibraryIdentifier/registrations/passTypeIdentifier/serialNumber

	db, err := getDbType(c)
	check(err)

	//1. Verify that the authentication token is correct.
	authToken := req.Header.Get("ApplePass")
	if !verifyToken(tokenPrivateKey, authToken, c.URLParams["serialNumber"], c.URLParams["passTypeIdentifier"]) {
		http.Error(res, "unauthorized", 401)
		return
	}

	var newRegister registerPass

	newRegister.PassTypeId = c.URLParams["passTypeIdentifier"]
	newRegister.SerialNumber = c.URLParams["serialNumber"]
	//newRegister.DeviceLibId = newDevice.DeviceLibId
	//db.Add("clientRegister", newRegister)
	db.DelByID(c.URLParams["deviceLibraryIdentifier"]) //Delete the serial and/or pasTypeID from the device listing. (delete device if contains no serials?)
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func logErrors(c web.C, res http.ResponseWriter, req *http.Request) {
	//POST webServiceURL/version/log

	//readJson(req, errorData)

	//log.Printf("pass log error", errorData)
}
