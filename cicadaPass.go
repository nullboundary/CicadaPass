package main

import (
	"encoding/base64"
	"github.com/zenazn/goji"
	"github.com/zenazn/goji/web"
	"log"
	"net/http"
	"strconv"
	"time"
)

var tokenPrivateKey = `y0yArOR5I\)rZT8Kj6NaaJs;{T:h0p1` //TODO: lets make a new key and put this somewhere safer!

var p12pass = "cicada" //TODO: Set in env variables

func main() {

	goji.Post("/pass", createPass)
	goji.Get("/pass/:version/passes/:passTypeIdentifier", getByPassTypeId)
	goji.Get("/pass/:version/passes/:passTypeIdentifier/:serialNumber", getLatestByPassTypeId)
	goji.Post("/pass/:version/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/:serialNumber", registerDevicePass)
	goji.Get("/pass/:version/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier", getPassSerialbyDevice)
	goji.Delete("/pass/:version/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/:serialNumber", unregisterDevice)
	goji.Post("/pass/:version/log", logErrors)

	goji.NotFound(NotFound)

	goji.Use(addDb)

	goji.Serve()
}

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

	uri, err := encodetoDataUri("icon.png", ".png") //TODO: read in images from form, not filesystem
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

	var newDevice device         //struct for registering with the device db
	var newRegister registerPass //struct for the new pass being added to the device
	var newPass pass             //data of the type of pass being added (used to get updated time tag)

	//POST request to webServiceURL/version/devices/deviceLibraryIdentifier/registrations/passTypeIdentifier/serialNumber

	if !accessToken(req.Header.Get("HTTP_AUTHORIZATION"), c) {
		http.Error(res, "unauthorized", 401)
		return
	}

	//2. Store the mapping between the device library identifier and the push token in the devices table.
	readJson(req, &newDevice)
	newDevice.DeviceLibId = c.URLParams["deviceLibraryIdentifier"]

	//3. Store the mapping between the pass (by pass type identifier and serial number) and the device library identifier in the registrations table
	if !db.FindByID("pass", c.URLParams["passTypeIdentifier"], &newPass) {
		http.Error(res, "passType not found", 404)
		return
	}

	newRegister.PassTypeId = c.URLParams["passTypeIdentifier"]
	newRegister.SerialNumber = c.URLParams["serialNumber"]       //set serial num
	newRegister.Updated = newPass.Updated                        //set the last updated time for this pass
	newDevice.PassList = append(newDevice.PassList, newRegister) //add the pass to the device passList
	if !db.Merge("clientDevices", newDevice.DeviceLibId, newDevice) {
		res.WriteHeader(http.StatusOK) //If the serial number is already registered for this device, return HTTP status 200.
		return
	}

	res.WriteHeader(http.StatusCreated) //If registration succeeds, return HTTP status 201.

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

	//4. Respond with this list of serial numbers and the latest update tag in a JSON payload
	type serialList struct {
		SerialNumbers []string `json:"serialNumbers"` //list of passes to be updated
		LastUpdated   int64    `json:"lastUpdated"`   //the time of the most recent pass update
	}
	var result serialList

	urlValue := req.URL.Query()
	var updatedTag int64
	updatedTagStr := urlValue.Get("passesUpdatedSince")
	if updatedTagStr != "" {
		updatedTag, err = strconv.ParseInt(updatedTagStr, 10, 64)
		check(err)
	}
	log.Printf("updated: %d", updatedTag)

	var userDevice device

	dLId := c.URLParams["deviceLibraryIdentifier"]

	//1. Look at the registrations table and determine which passes the device is registered for.
	if !db.FindByID("clientDevices", dLId, &userDevice) {
		http.Error(res, "device not found", 404)
		return
	}

	passList := userDevice.PassList

	for i := range passList { //TODO: Could this be sorted on the db?
		//2. Look at the passes table and determine which passes have changed since the given tag. Don’t include serial numbers of passes that the device didn’t register for.
		if passList[i].Updated.Unix() >= updatedTag {
			result.SerialNumbers = append(result.SerialNumbers, passList[i].SerialNumber)

			//3. Compare the update tags for each pass that has changed and determine which one is the latest.
			if passList[i].Updated.Unix() >= result.LastUpdated {
				result.LastUpdated = passList[i].Updated.Unix()

			}
		}
	}

	writeJson(res, result)

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

	if !accessToken(req.Header.Get("HTTP_AUTHORIZATION"), c) {
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

	if !accessToken(req.Header.Get("HTTP_AUTHORIZATION"), c) {
		http.Error(res, "unauthorized", 401)
		return
	}

	var newRegister registerPass

	newRegister.PassTypeId = c.URLParams["passTypeIdentifier"]
	newRegister.SerialNumber = c.URLParams["serialNumber"]
	//newRegister.DeviceLibId = newDevice.DeviceLibId
	//db.Add("clientRegister", newRegister)
	db.DelByID("clientDevices", c.URLParams["deviceLibraryIdentifier"]) //Delete the serial and/or pasTypeID from the device listing. (delete device if contains no serials?)
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func logErrors(c web.C, res http.ResponseWriter, req *http.Request) {
	//POST webServiceURL/version/log

	type errorLog struct {
		message string `json:"error"`
	}
	var printErr errorLog

	readJson(req, &printErr) //read in the error

	log.Printf("error Message: %s", printErr.message) //log it

}
