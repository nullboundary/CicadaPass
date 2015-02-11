package main

import (
	"bitbucket.org/cicadaDev/utils"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"github.com/hashicorp/logutils"
	"github.com/zenazn/goji/graceful"
	"github.com/zenazn/goji/web"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var tokenPrivateKey = []byte(`y0yArOR5I\)rZT8Kj6NaaJs;{T:h0p1`) //TODO: lets make a new key and put this somewhere safer!
var webServiceURL = "https://local.pass.ninja:8001"
var p12pass = "cicada" //TODO: Set in env variables

type downloadLog struct {
	Id         string    `json:"passid" gorethink:"passid" valid:"required"`                          //Pass ID - used for updating, but not sharing
	UserId     string    `json:"-" gorethink:"userid,omitempty"`                                      //The Id of the pass creator
	PassType   string    `json:"passtype,omitempty" gorethink:"passtype,omitempty" valid:"passtypes"` //The pass type, boardingpass, coupon, etc.
	Downloaded time.Time `json:"downloaded" gorethink:"downloaded" valid:"required"`                  //when the pass was downloaded
}

func init() {
	//add custom validator functions
	addValidators()

	//setup logutils log levels
	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "WARN", "ERROR"},
		MinLevel: "DEBUG",
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)

}

func main() {

	mux := web.New()

	mux.Get("/pass/:version/passes/:passTypeIdentifier", getByPassTypeId) //TODO: maybe :version should be regex?
	mux.Get("/pass/:version/passes/:passTypeIdentifier/:serialNumber", getLatestByPassTypeId)
	mux.Post("/pass/:version/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/:serialNumber", registerDevicePass)
	mux.Get("/pass/:version/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier", getPassSerialbyDevice)
	mux.Delete("/pass/:version/devices/:deviceLibraryIdentifier/registrations/:passTypeIdentifier/:serialNumber", unregisterDevice)
	mux.Post("/pass/:version/log", logErrors)

	mux.NotFound(NotFound)

	mux.Use(AddDb)

	//customCA Server is only used for testing
	customCAServer := &graceful.Server{Addr: ":10443", Handler: mux}
	customCAServer.TLSConfig = addRootCA("tls/myCA.cer")
	customCAServer.ListenAndServeTLS("tls/mycert1.cer", "tls/mycert1.key")

	//graceful.ListenAndServeTLS(":10443", "tls/mycert1.cer", "tls/mycert1.key", mux)
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func addRootCA(filepath string) *tls.Config {

	severCert, err := ioutil.ReadFile(filepath)
	utils.Check(err)

	cAPool := x509.NewCertPool()
	cAPool.AppendCertsFromPEM(severCert)

	tlc := &tls.Config{
		RootCAs:    cAPool,
		MinVersion: tls.VersionTLS10,
	}

	return tlc

}

//////////////////////////////////////////////////////////////////////////
//
//	getByPassTypeId Handler
//
//
//////////////////////////////////////////////////////////////////////////
func getByPassTypeId(c web.C, res http.ResponseWriter, req *http.Request) {

	log.Println("[DEBUG] getByPassTypeId")

	db, err := GetDbType(c)
	utils.Check(err)

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

	//POST request to webServiceURL/version/devices/deviceLibraryIdentifier/registrations/passTypeIdentifier/serialNumber
	log.Printf("[DEBUG] registerDevicePass")

	db, err := GetDbType(c)
	utils.Check(err)

	var newDevice device         //struct for registering with the device db
	var newRegister registerPass //struct for the new pass being added to the device
	var newPass pass             //data of the type of pass being added (used to get updated time tag)

	if !accessToken(req.Header.Get("HTTP_AUTHORIZATION"), c) {
		log.Printf("[WARN] access token unauthorized: %s", req.Header.Get("HTTP_AUTHORIZATION"))
		http.Error(res, "unauthorized", 401)
		return
	}

	//2. Store the mapping between the device library identifier and the push token in the devices table.
	utils.ReadJson(req, &newDevice)
	newDevice.DeviceLibId = c.URLParams["deviceLibraryIdentifier"]

	//3. Store the mapping between the pass (by pass type identifier and serial number) and the device library identifier in the registrations table
	if !db.FindById("pass", c.URLParams["passTypeIdentifier"], &newPass) {
		log.Printf("[WARN] pass not found: %s", c.URLParams["passTypeIdentifier"])
		http.Error(res, "passType not found", 404)
		return
	}

	newRegister.PassTypeId = c.URLParams["passTypeIdentifier"]
	newRegister.SerialNumber = c.URLParams["serialNumber"]       //set serial num
	newRegister.Updated = newPass.Updated                        //set the last updated time for this pass
	newDevice.PassList = append(newDevice.PassList, newRegister) //add the pass to the device passList
	if !db.Merge("clientDevices", "deviceLibId", newDevice.DeviceLibId, newDevice) {
		log.Printf("[DEBUG] new device pass merged or added: %s", newDevice.DeviceLibId)
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
	log.Printf("[DEBUG] getPassSerialbyDevice")

	db, err := GetDbType(c)
	utils.Check(err)

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
		utils.Check(err)
	}
	log.Printf("[DEBUG] updated: %d", updatedTag)

	var userDevice device

	dLId := c.URLParams["deviceLibraryIdentifier"]

	//1. Look at the registrations table and determine which passes the device is registered for.
	if !db.FindById("clientDevices", dLId, &userDevice) {
		log.Printf("[WARN] device not found: %s", dLId)
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

	utils.WriteJson(res, result, true)

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func getLatestByPassTypeId(c web.C, res http.ResponseWriter, req *http.Request) {
	//GET request to webServiceURL/version/passes/passTypeIdentifier/serialNumber
	log.Printf("[DEBUG] getLatestByPassTypeId")

	//TODO: Support standard HTTP caching on this endpoint: check for the If-Modified-Since header and return HTTP status code 304 if the pass has not changed.

	db, err := GetDbType(c)
	utils.Check(err)

	if !accessToken(req.Header.Get("HTTP_AUTHORIZATION"), c) {
		log.Printf("[WARN] access token unauthorized: %s", req.Header.Get("HTTP_AUTHORIZATION"))
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

	db, err := GetDbType(c)
	utils.Check(err)

	if !accessToken(req.Header.Get("HTTP_AUTHORIZATION"), c) {
		log.Printf("[WARN] access token unauthorized: %s", req.Header.Get("HTTP_AUTHORIZATION"))
		http.Error(res, "unauthorized", 401)
		return
	}

	var newRegister registerPass

	newRegister.PassTypeId = c.URLParams["passTypeIdentifier"]
	newRegister.SerialNumber = c.URLParams["serialNumber"]
	//newRegister.DeviceLibId = newDevice.DeviceLibId
	//db.Add("clientRegister", newRegister)
	db.DelById("clientDevices", c.URLParams["deviceLibraryIdentifier"]) //Delete the serial and/or pasTypeID from the device listing. (delete device if contains no serials?)
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

	utils.ReadJson(req, &printErr) //read in the error

	log.Printf("[ERROR] : %s", printErr.message) //log it

}
