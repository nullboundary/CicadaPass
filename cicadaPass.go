package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bitbucket.org/cicadaDev/datamodels"
	"bitbucket.org/cicadaDev/utils"
	log "github.com/Sirupsen/logrus"
	"github.com/zenazn/goji/graceful"
	"github.com/zenazn/goji/web"
	"github.com/zenazn/goji/web/middleware"
)

var (
	tokenPrivateKey = []byte(``) //TODO: lets make a new key and put this somewhere safer!
	webServiceURL   = "https://example.com/"                //the url of this service (https://vendor.pass.ninja)
	pempass         = ""                                        //the password for pass pem keys
	keyMap          map[string][]byte                           //map of pem keys
	certMap         map[string][]byte                           //map of certificates
	bindURL         string                                      //flag var for binding to a specific port
	secretKeyRing   = "/certs/.secring.gpg"                     //crypt set -keyring .pubring.gpg -endpoint http://10.1.42.1:4001 /passcerts/keypass keypass.json
)

type downloadLog struct {
	Id         string    `json:"passid" gorethink:"passid" valid:"required"`                          //Pass ID - used for updating, but not sharing
	UserId     string    `json:"-" gorethink:"userid,omitempty"`                                      //The Id of the pass creator
	PassType   string    `json:"passtype,omitempty" gorethink:"passtype,omitempty" valid:"passtypes"` //The pass type, boardingpass, coupon, etc.
	Downloaded time.Time `json:"downloaded" gorethink:"downloaded" valid:"required"`                  //when the pass was downloaded
}

func init() {

	flag.StringVar(&bindURL, "bindurl", "http://localhost:8001", "The public ip address and port number for this server to bind to")
	flag.Parse()

	//add custom validator functions
	addValidators()

	//setup logutils log levels
	log.SetLevel(log.DebugLevel)

	//load etcd service url from env variables
	etcdAddr := utils.SetEtcdURL()
	log.WithField("etcdAddr", etcdAddr).Infoln("set etcd from env variable")

	//load crypt pass key from json file
	var keyPassMap map[string]interface{}
	keyPass, err := utils.GetCryptKey(secretKeyRing, "/passcerts/keypass")
	if err != nil {
		log.Errorf("error getting pass keys from etcd: %s", err)
	}
	err = json.Unmarshal(keyPass, &keyPassMap)
	if err != nil {
		log.Errorf("error getting unmarshalling pass keys from etcd: %s", err)
	}
	pempass = keyPassMap["keypass"].(string)

	keyMap = make(map[string][]byte)
	certMap = make(map[string][]byte)

	passTypes := []string{"boardingpass", "coupon", "eventticket", "storecard"} //TODO: generic
	loadPassKeysCerts(passTypes...)
}

func main() {

	mux := web.New()
	mux.Use(middleware.EnvInit)

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
	if err != nil {
		log.WithField("filepath", filepath).Fatalf("error loading Root CA file %v", err)
	}

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

	log.WithField("url", req.URL.Path[1:]).Debugln("getByPassTypeId")

	db, err := GetDbType(c)
	utils.Check(err)

	passId := c.URLParams["passTypeIdentifier"]
	dlPass := dataModels.NewPass()

	//search for the pass by ID in the db
	if ok, _ := db.FindByIdx("passMutate", "filename", passId, &dlPass); ok {
		log.WithField("passid", passId).Debugln("found pass in passMutate table")
		err := db.DelById("passMutate", passId) //TODO: should be removed ONLY after pass is registered in device.
		if err != nil {
			log.Errorf("error deleting from passMutate table %s", err)
			return
		}
	} else if ok, _ := db.FindByIdx("pass", "filename", passId, &dlPass); ok {
		log.WithField("passid", passId).Debugln("found pass in passMutate table")
	} else {
		log.WithField("passid", passId).Warnln("pass not found")
		http.Error(res, "pass not found", 404)
		return
	}

	passUser := dataModels.NewUser()

	//get pass creator user model
	if ok, _ := db.FindById("users", dlPass.UserId, &passUser); !ok {
		log.WithField("userid", dlPass.UserId).Warnln("user not found")
		utils.JsonErrorResponse(res, fmt.Errorf(http.StatusText(http.StatusNotFound)), http.StatusNotFound)
		return
	}

	if ok := limitDownloads(dlPass, passUser); !ok {
		log.WithField("userid", dlPass.UserId).Warnln("exceeded plan download limit")
		utils.JsonErrorResponse(res, fmt.Errorf("Exceeded Plan Download Limit"), http.StatusForbidden)
		return
	}

	//TODO some db magic can probably do this more effectively
	//decrement 1 pass download and save the decrement.
	dlPass.PassRemain--
	_, err = db.Merge("pass", dlPass.Id, false, dlPass)
	if err != nil {
		log.WithField("pass", dlPass.Name).Errorf("error merging pass %s", err)
		utils.JsonErrorResponse(res, fmt.Errorf("a conflict has occurred"), http.StatusConflict)
		return
	}

	//add backfield copy and terms here.
	err = addBackNotice(dlPass)
	if err != nil {
		log.WithField("pass", dlPass.Name).Errorf("error adding backfield notice %s", err)
		utils.JsonErrorResponse(res, fmt.Errorf("an error has occurred"), http.StatusInternalServerError)
		return
	}

	//generate a unique serial number for this pass being downloaded added to file name
	serialHash := utils.HashSha1Bytes([]byte(req.UserAgent() + utils.RandomStr(16) + time.Now().String()))
	fileName := []byte(dlPass.FileName + "|")
	serialBytes := append(fileName, serialHash...)
	serial := base64.URLEncoding.EncodeToString(serialBytes)

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
	log.WithField("url", req.URL.Path[1:]).Debugln("registerDevicePass")

	db, err := GetDbType(c)
	utils.Check(err)

	var newDevice dataModels.Device         //struct for registering with the device db
	var newRegister dataModels.RegisterPass //struct for the new pass being added to the device
	newPass := dataModels.NewPass()         //var newPass pass             //data of the type of pass being added (used to get updated time tag)

	if !accessToken(req.Header.Get("Authorization"), c) {
		log.WithField("token", req.Header.Get("Authorization")).Warnln("access token unauthorized")
		http.Error(res, http.StatusText(401), http.StatusUnauthorized)
		return
	}

	//2. Store the mapping between the device library identifier and the push token in the devices table.
	err = utils.ReadJson(req, &newDevice)
	if err != nil {
		log.Errorf("read json error %s", err)
		http.Error(res, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	newDevice.DeviceLibId = c.URLParams["deviceLibraryIdentifier"]

	//use the serial contains filename to find the pass!
	decodedSerial, err := base64.URLEncoding.DecodeString(c.URLParams["serialNumber"])
	if err != nil {
		log.Errorf("base64 decode error %s", err)
		http.Error(res, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	fileserial := strings.Split(string(decodedSerial), "|")

	//3. Store the mapping between the pass (by pass type identifier and serial number) and the device library identifier in the registrations table
	if ok, err := db.FindByIdx("pass", "filename", fileserial[0], &newPass); !ok {
		if err != nil {
			log.WithField("filename", fileserial[0]).Errorf("find pass by index error %s", err)
		} else {
			log.WithField("filename", fileserial[0]).Warnf("pass not found")
		}
		http.Error(res, "passType not found", http.StatusNotFound)
		return
	}

	newRegister.PassTypeId = c.URLParams["passTypeIdentifier"]
	newRegister.SerialNumber = c.URLParams["serialNumber"]       //set serial num
	newRegister.Updated = newPass.Updated                        //set the last updated time for this pass
	newDevice.PassList = append(newDevice.PassList, newRegister) //add the pass to the device passList
	if ok, err := db.Merge("clientDevices", newDevice.DeviceLibId, false, newDevice); !ok {
		if err != nil {
			log.Errorf("merge pass to clientDevice table error %s", err)
			res.WriteHeader(http.StatusConflict) //If the serial number is already registered for this device, return HTTP status 200.
		} else { //no error, but no change (already registered)
			log.WithField("deviceid", newDevice.DeviceLibId).Debugf("new device already added")
			res.WriteHeader(http.StatusOK) //If the serial number is already registered for this device, return HTTP status 200.
		}
		return
	}

	log.WithField("deviceid", newDevice.DeviceLibId).Debugf("new device pass merged or added")
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
	log.WithField("url", req.URL.Path[1:]).Debugln("getPassSerialbyDevice")

	db, err := GetDbType(c)
	utils.Check(err)

	//4. Respond with this list of serial numbers and the latest update tag in a JSON payload
	type serialList struct {
		SerialNumbers []string `json:"serialNumbers"` //list of passes to be updated
		LastUpdated   string   `json:"lastUpdated"`   //the time of the most recent pass update
	}
	var result serialList

	urlValue := req.URL.Query()
	var updatedTag int64
	updatedTagStr := urlValue.Get("passesUpdatedSince")
	if updatedTagStr != "" {
		updatedTag, err = strconv.ParseInt(updatedTagStr, 10, 64)
		if err != nil {
			log.WithField("updateTag", updatedTagStr).Errorf("error parsing update tag %s", err)
		}
	}
	log.Debugf("updated: %d", updatedTag)

	var userDevice dataModels.Device

	dLId := c.URLParams["deviceLibraryIdentifier"]

	//1. Look at the registrations table and determine which passes the device is registered for.
	if ok, err := db.FindById("clientDevices", dLId, &userDevice); !ok {
		if err != nil {
			log.WithField("deviceLibraryID", dLId).Errorf("error finding clientDevice %s", err)
		} else {
			log.WithField("deviceLibraryID", dLId).Warnf("device not found")
		}
		http.Error(res, "device not found", 404)
		return
	}

	passList := userDevice.PassList

	lastUpdate := updatedTag
	for i := range passList {
		//2. Look at the passes table and determine which passes have changed since the given tag. Don’t include serial numbers of passes that the device didn’t register for.
		if passList[i].Updated.Unix() > updatedTag {
			result.SerialNumbers = append(result.SerialNumbers, passList[i].SerialNumber)

			//3. Compare the update tags for each pass that has changed and determine which one is the latest.
			if passList[i].Updated.Unix() > lastUpdate {
				lastUpdate = passList[i].Updated.Unix()
			}

		}
	}

	if result.SerialNumbers == nil || len(result.SerialNumbers) == 0 {
		log.Debugln("No Passes to Update")
		res.WriteHeader(http.StatusNoContent)
		return
	}

	result.LastUpdated = fmt.Sprintf("%d", lastUpdate) //convert the unix timestamp to a string
	err = utils.WriteJson(res, result, true)
	if err != nil {
		log.Errorf("error writing json to response %s", err)
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
	log.WithField("url", req.URL.Path[1:]).Debugln("getLatestByPassTypeId")

	db, err := GetDbType(c)
	utils.Check(err)

	if !accessToken(req.Header.Get("Authorization"), c) {
		log.WithField("token", req.Header.Get("Authorization")).Warnln("access token unauthorized")
		http.Error(res, http.StatusText(401), 401)
		return
	}

	passId := c.URLParams["passTypeIdentifier"]
	dlPass := dataModels.NewPass()

	//use the serial contains filename to find the pass!
	decodedSerial, err := base64.URLEncoding.DecodeString(c.URLParams["serialNumber"])
	if err != nil {
		log.Errorf("base64 decode error %s", err)
		http.Error(res, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	fileserial := strings.Split(string(decodedSerial), "|")

	//search for the pass by ID in the db
	if ok, _ := db.FindByIdx("passMutate", "filename", fileserial[0], &dlPass); ok {
		log.WithField("filename", fileserial[0]).Debugf("found pass in passMutate table")
		err := db.DelById("passMutate", passId) //TODO: should be removed ONLY after pass is registered in device.
		if err != nil {
			log.Errorf("error deleting mutate pass %s", err)
			return
		}
	} else if ok, _ := db.FindByIdx("pass", "filename", fileserial[0], &dlPass); ok {
		log.WithField("filename", fileserial[0]).Debugf("found pass in pass table")
	} else {
		log.WithField("filename", fileserial[0]).Warnf("pass not found")
		http.Error(res, "pass not found", 404)
		return
	}

	modtime := dlPass.Updated
	if t, err := time.Parse(http.TimeFormat, req.Header.Get("If-Modified-Since")); err == nil && modtime.Before(t.Add(1*time.Second)) {
		res.WriteHeader(http.StatusNotModified)
		return
	}

	//add backfield copy and terms here.
	err = addBackNotice(dlPass)
	if err != nil {
		log.WithField("pass", dlPass.Name).Errorf("error adding backfield notice %s", err)
		utils.JsonErrorResponse(res, fmt.Errorf("an error has occurred"), http.StatusInternalServerError)
		return
	}

	generatePass(dlPass, c.URLParams["serialNumber"], res, db)

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

	if !accessToken(req.Header.Get("Authorization"), c) {
		log.WithField("token", req.Header.Get("Authorization")).Warnln("access token unauthorized")
		http.Error(res, http.StatusText(401), 401)
		return
	}
	log.WithField("serial", c.URLParams["serialNumber"]).Debugf("unregisterDevice")

	var userDevice dataModels.Device

	serialNumber := c.URLParams["serialNumber"]
	dLId := c.URLParams["deviceLibraryIdentifier"]

	if ok, err := db.FindById("clientDevices", dLId, &userDevice); !ok {
		if err != nil {
			log.WithField("deviceLibraryID", dLId).Errorf("error finding clientDevice %s", err)
		} else {
			log.WithField("deviceLibraryID", dLId).Warnf("device not found")
		}
		http.Error(res, "device not found", 404)
		return
	}
	//TODO: use the db to do search and delete pass from passlist
	for i := range userDevice.PassList {
		//look for matching pass serialnumbers
		if userDevice.PassList[i].SerialNumber == serialNumber {
			//delete pass from slice
			userDevice.PassList = append(userDevice.PassList[:i], userDevice.PassList[i+1:]...)
		}
	}

	//merge results or delete device if zero passes
	if len(userDevice.PassList) > 0 {
		_, err := db.Merge("clientDevices", userDevice.DeviceLibId, false, userDevice)
		if err != nil {
			log.WithField("deviceLibraryID", userDevice.DeviceLibId).Errorf("error merging clientDevice %s", err)
			res.WriteHeader(http.StatusConflict)
			return
		}

	} else {
		err = db.DelById("clientDevices", c.URLParams["deviceLibraryIdentifier"]) //Delete the serial and/or pasTypeID from the device listing. (delete device if contains no serials?)
		if err != nil {
			log.WithField("deviceLibraryID", c.URLParams["deviceLibraryIdentifier"]).Errorf("error deleting clientDevice %s", err)
			http.Error(res, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	res.WriteHeader(http.StatusOK)

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
		Logs []string `json:"logs"`
	}
	var printErr errorLog

	err := utils.ReadJson(req, &printErr) //read in the error
	if err != nil {
		log.Errorf("error reading error log json 0_o %s", err)
	}

	for _, logMsg := range printErr.Logs {
		log.Errorf("passbook client error: %s", logMsg) //log it
	}
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
