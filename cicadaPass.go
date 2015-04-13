package main

import (
	"bitbucket.org/cicadaDev/utils"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
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

var (
	tokenPrivateKey = []byte(`y0yArOR5I\)rZT8Kj6NaaJs;{T:h0p1`) //TODO: lets make a new key and put this somewhere safer!
	webServiceURL   = "https://local.pass.ninja:8001"           //the url of this service (https://vendor.pass.ninja)
	pempass         = ""                                        //the password for pass pem keys
	keyMap          map[string][]byte                           //map of pem keys
	certMap         map[string][]byte                           //map of certificates
	bindUrl         string                                      //flag var for binding to a specific port
	secretKeyring   = "/certs/.secring.gpg"                     //crypt set -keyring .pubring.gpg -endpoint http://10.1.42.1:4001 /passcerts/keypass keypass.json
)

type downloadLog struct {
	Id         string    `json:"passid" gorethink:"passid" valid:"required"`                          //Pass ID - used for updating, but not sharing
	UserId     string    `json:"-" gorethink:"userid,omitempty"`                                      //The Id of the pass creator
	PassType   string    `json:"passtype,omitempty" gorethink:"passtype,omitempty" valid:"passtypes"` //The pass type, boardingpass, coupon, etc.
	Downloaded time.Time `json:"downloaded" gorethink:"downloaded" valid:"required"`                  //when the pass was downloaded
}

func init() {

	flag.StringVar(&bindUrl, "bindurl", "http://localhost:8001", "The public ip address and port number for this server to bind to")
	flag.Parse()

	//add custom validator functions
	addValidators()

	//setup logutils log levels
	filter := &logutils.LevelFilter{
		Levels:   []logutils.LogLevel{"DEBUG", "INFO", "WARN", "ERROR"},
		MinLevel: "DEBUG",
		Writer:   os.Stderr,
	}
	log.SetOutput(filter)

	//load etcd service url from env variables
	etcdAddr := utils.SetEtcdURL()
	log.Printf("[INFO] etcd: %s", etcdAddr)

	//load crypt pass key from json file
	var keyPassMap map[string]interface{}
	keyPass, err := utils.GetCryptKey(secretKeyring, "/passcerts/keypass")
	utils.Check(err)
	err = json.Unmarshal(keyPass, &keyPassMap)
	utils.Check(err)
	pempass = keyPassMap["keypass"].(string)

	keyMap = make(map[string][]byte)
	certMap = make(map[string][]byte)

	passTypes := []string{"boardingpass", "coupon", "eventticket", "storecard"} //TODO: generic
	loadPassKeysCerts(passTypes...)
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

	//annouce the server on etcd for vulcand
	announceEtcd()

	//customCA Server is only used for testing
	customCAServer := &graceful.Server{Addr: ":443", Handler: mux}
	customCAServer.TLSConfig = addRootCA("/certs/tls/myCA.cer")
	customCAServer.ListenAndServeTLS("/certs/tls/mycert1.cer", "/certs/tls/mycert1.key")

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

	passId := c.URLParams["passTypeIdentifier"]
	var dlPass pass

	//search for the pass by ID in the db
	if ok, _ := db.FindByIdx("passMutate", "filename", passId, &dlPass); ok {
		log.Printf("[DEBUG] found pass: %s in passMutate table", passId)
		err := db.DelById("passMutate", passId) //TODO: should be removed ONLY after pass is registered in device.
		if err != nil {
			log.Printf("[ERROR] %s", err)
			return
		}
	} else if ok, _ := db.FindByIdx("pass", "filename", passId, &dlPass); ok {
		log.Printf("[DEBUG] found pass: %s in pass table", passId)
	} else {
		log.Printf("[WARN] pass: %s not found", passId)
		http.Error(res, "pass not found", 404)
		return
	}

	passUser := &userModel{}

	//get pass creator user model
	if ok, _ := db.FindById("users", dlPass.UserId, &passUser); !ok {
		log.Printf("[ERROR] user not found %s", dlPass.UserId)
		utils.JsonErrorResponse(res, fmt.Errorf(http.StatusText(http.StatusNotFound)), http.StatusNotFound)
		return
	}

	//decrement 1 pass download
	dlPass.PassRemain -= 1

	//limit pass download for freeplan
	if dlPass.PassRemain < 0 && passUser.SubPlan == FreePlan {
		log.Printf("[ERROR] Exceeded Plan Download Limit %s", dlPass.UserId)
		utils.JsonErrorResponse(res, fmt.Errorf("Exceeded Plan Download Limit"), http.StatusUnauthorized)
		return
	}

	//generate a unique serial number for this pass being downloaded
	serialHash := utils.HashSha1Bytes([]byte(req.UserAgent() + time.Now().String()))
	serial := base64.URLEncoding.EncodeToString(serialHash)

	generatePass(dlPass, serial, res, db)

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
		http.Error(res, http.StatusText(401), 401)
		return
	}

	//2. Store the mapping between the device library identifier and the push token in the devices table.
	utils.ReadJson(req, &newDevice)
	newDevice.DeviceLibId = c.URLParams["deviceLibraryIdentifier"]

	//3. Store the mapping between the pass (by pass type identifier and serial number) and the device library identifier in the registrations table
	if ok, err := db.FindById("pass", c.URLParams["passTypeIdentifier"], &newPass); !ok {
		if err != nil {
			log.Printf("[ERROR] %s", err)
		} else {
			log.Printf("[WARN] pass not found: %s", c.URLParams["passTypeIdentifier"])
		}
		http.Error(res, "passType not found", 404)
		return
	}

	newRegister.PassTypeId = c.URLParams["passTypeIdentifier"]
	newRegister.SerialNumber = c.URLParams["serialNumber"]       //set serial num
	newRegister.Updated = newPass.Updated                        //set the last updated time for this pass
	newDevice.PassList = append(newDevice.PassList, newRegister) //add the pass to the device passList
	if ok, err := db.Merge("clientDevices", "deviceLibId", newDevice.DeviceLibId, newDevice); !ok {
		if err != nil {
			log.Printf("[ERROR] %s", err)
			res.WriteHeader(http.StatusConflict) //If the serial number is already registered for this device, return HTTP status 200.
		} else { //no error, but no change (already registered)
			log.Printf("[DEBUG] new device already added: %s", newDevice.DeviceLibId)
			res.WriteHeader(http.StatusOK) //If the serial number is already registered for this device, return HTTP status 200.
		}
		return
	}

	log.Printf("[DEBUG] new device pass merged or added: %s", newDevice.DeviceLibId)
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
	if ok, err := db.FindById("clientDevices", dLId, &userDevice); !ok {
		if err != nil {
			log.Printf("[ERROR] %s", err)
		} else {
			log.Printf("[WARN] device not found: %s", dLId)
		}
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
		http.Error(res, http.StatusText(401), 401)
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
		http.Error(res, http.StatusText(401), 401)
		return
	}

	var newRegister registerPass

	newRegister.PassTypeId = c.URLParams["passTypeIdentifier"]
	newRegister.SerialNumber = c.URLParams["serialNumber"]
	//newRegister.DeviceLibId = newDevice.DeviceLibId
	//db.Add("clientRegister", newRegister)
	err = db.DelById("clientDevices", c.URLParams["deviceLibraryIdentifier"]) //Delete the serial and/or pasTypeID from the device listing. (delete device if contains no serials?)
	if err != nil {
		log.Printf("[ERROR] %s", err)
		http.Error(res, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
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

//////////////////////////////////////////////////////////////////////////
//
// NotFound is a 404 handler.
//
//
//////////////////////////////////////////////////////////////////////////
func NotFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Resource Not Found", 404) //TODO: add 404 error message
}
