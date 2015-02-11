package main

import (
	"archive/zip"
	"bitbucket.org/cicadaDev/gocertsigner"
	"bitbucket.org/cicadaDev/storer"
	"bitbucket.org/cicadaDev/utils"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/slugmobile/govalidator"
	"github.com/zenazn/goji/web"
	"hash/fnv"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
	"unicode"
)

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func generatePass(passId string, serialNum string, res http.ResponseWriter, db storer.Storer) {

	var dlPass pass

	//search for the pass by ID in the db
	if db.FindByIdx("passMutate", "filename", passId, &dlPass) {
		log.Printf("[DEBUG] found pass: %s in passMutate table", passId)
		db.DelById("passMutate", passId) //TODO: should be removed ONLY after pass is registered in device.
	} else if db.FindByIdx("pass", "filename", passId, &dlPass) {
		log.Printf("[DEBUG] found pass: %s in pass table", passId)
	} else {
		log.Printf("[WARN] pass: %s not found", passId)
		http.Error(res, "pass not found", 404)
		return
	}

	//update pass doc
	dlPass.KeyDoc.SerialNumber = serialNum
	dlPass.KeyDoc.PassTypeIdentifier = "pass.ninja.pass.storecard" //set via etcd?
	dlPass.KeyDoc.TeamIdentifier = "F8QZ9HX5A6"                    //set via etcd
	dlPass.KeyDoc.FormatVersion = 1
	dlPass.KeyDoc.WebServiceURL = webServiceURL
	dlPass.KeyDoc.AuthenticationToken = utils.GenerateToken(tokenPrivateKey, serialNum, passId)

	//log pass download info: time, pass id, serialnum, user id.
	var dlLog downloadLog
	dlLog.Id = dlPass.Id
	dlLog.PassType = dlPass.KeyDoc.PassTypeIdentifier
	dlLog.UserId = dlPass.UserId
	dlLog.Downloaded = time.Now()

	if !db.Add("downloadLog", dlLog) {
		log.Printf("[ERROR] error adding pass download record: %s to db", dlLog.Id)
		return
	}

	//make manifestdoc map for storing sha1 hashes
	dlPass.ManifestDoc = make(map[string]string)

	//validate the struct before generating a pass
	_, err := govalidator.ValidateStruct(dlPass)
	if err != nil {
		utils.Check(err)
		http.Error(res, "malformed pass data, cannot build pass", http.StatusInternalServerError)
		return
	}

	// Create a new zip archive.
	res.Header().Set("Content-Type", "application/vnd.apple.pkpass") //sets the extension to pkpass
	//Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w := zip.NewWriter(res)
	defer w.Close()

	//add the pass.json file to the zip pass
	file := addToZipFile(w, "pass.json")
	keyDocBytes, err := json.MarshalIndent(dlPass.KeyDoc, "", "  ") //pretty print json doc
	utils.Check(err)
	file.Write(keyDocBytes)

	//compute sha1 hash for pass.json
	dlPass.ManifestDoc["pass.json"] = fmt.Sprintf("%x", hashSha1Bytes(keyDocBytes))

	//add all images to the pass zip
	for i := range dlPass.Images {

		fileExt, imageBytes := decodetoBytes(dlPass.Images[i].ImageData, "png")
		fileName := dlPass.Images[i].ImageName + "." + fileExt
		file = addToZipFile(w, fileName)
		_, err := file.Write(imageBytes)
		utils.Check(err)

		//compute sha1 hash for each image file, add to manifest doc
		dlPass.ManifestDoc[fileName] = fmt.Sprintf("%x", hashSha1Bytes(imageBytes))
	}

	//add the manifest.json file to the zip pass
	file = addToZipFile(w, "manifest.json")
	//read in certificates and manifest as bytes
	manifestBytes, err := json.MarshalIndent(dlPass.ManifestDoc, "", "  ")
	utils.Check(err)
	file.Write(manifestBytes)

	//TODO: get documents and stuff from db or etcd
	pemKey := goCertSigner.FileToBytes("passCerts/pass.ninja.storecard.key.pem")
	x509cert := goCertSigner.FileToBytes("passCerts/pass.ninja.storecard.cer")
	caCert := goCertSigner.FileToBytes("passCerts/AppleWWDRCA.cer")
	signature, err := goCertSigner.SignWithX509PEM(manifestBytes, x509cert, pemKey, p12pass, caCert)
	utils.Check(err)

	file = addToZipFile(w, "signature")
	_, err = file.Write(signature)
	utils.Check(err)

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func addToZipFile(zWrite *zip.Writer, fileName string) io.Writer {

	var header zip.FileHeader
	header.Name = fileName
	header.Method = zip.Deflate         //compression method
	header.SetModTime(time.Now().UTC()) //sets modify and create times
	header.SetMode(0644)                //set all files to -rw-r--r--
	file, err := zWrite.CreateHeader(&header)
	utils.Check(err)

	return file

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func hashSha1Json(jsonData interface{}) []byte {

	//compute sha1 hash for json
	hash := sha1.New()
	enc := json.NewEncoder(hash) //json encode writes to the hash function
	enc.Encode(jsonData)
	return hash.Sum(nil)
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func hashSha1Bytes(hashBytes []byte) []byte {

	//compute sha1 hash of bytes
	hash := sha1.New()
	n, err := hash.Write(hashBytes)
	if n != len(hashBytes) || err != nil {
		panic(err)
	}
	return hash.Sum(nil)

}

//////////////////////////////////////////////////////////////////////////
//
//	generate a hash fnv1a hash. Fast, unique, but insecure! use only for ids and such.
//  https://programmers.stackexchange.com/questions/49550/which-hashing-algorithm-is-best-for-uniqueness-and-speed
//
//////////////////////////////////////////////////////////////////////////
func generateFnvHashId(hashSeeds ...string) uint32 {

	inputString := strings.Join(hashSeeds, "")

	var randomness int32
	binary.Read(rand.Reader, binary.LittleEndian, &randomness) //add a little randomness
	inputString = fmt.Sprintf("%s%x", inputString, randomness)

	h := fnv.New32a()
	h.Write([]byte(inputString))
	return h.Sum32()

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func accessToken(authString string, c web.C) bool {

	//1. Verify that the authentication token is correct.
	header := strings.Split(authString, " ")
	if len(header) < 2 {
		return false //header is malformed
	}
	authToken := header[1] //take the second value "applePass token"
	if ok, err := utils.VerifyToken(tokenPrivateKey, authToken, c.URLParams["serialNumber"], c.URLParams["passTypeIdentifier"]); !ok {

		if err != nil {
			utils.Check(err)
		}
		return false //verify failed
	}

	return true

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

//////////////////////////////////////////////////////////////////////////
//
// encodetoDataUri
//
//
//////////////////////////////////////////////////////////////////////////
func encodetoDataUri(fileName string, mimeType string, allowTypes ...string) (string, error) {

	file, _ := os.Open(fileName) //TODO: change to read in through form or json
	defer file.Close()

	fileInfo, _ := file.Stat() // FileInfo interface
	size := fileInfo.Size()    // file size

	data := make([]byte, size)

	contentType := path.Ext(fileName)

	typeFound := false
	for _, fileType := range allowTypes { //match the type with the allowed types
		if contentType == fileType {
			typeFound = true
			break
		}
	}

	if !typeFound {
		err := fmt.Errorf("[Error] file type: %s not allowed", contentType)
		return "", err
	}

	file.Read(data)

	return fmt.Sprintf("data:%s;base64,%s", mimeType, base64.StdEncoding.EncodeToString(data)), nil
}

//////////////////////////////////////////////////////////////////////////
//
// decodetoBytes
//
//
//////////////////////////////////////////////////////////////////////////
func decodetoBytes(str string, fileType string) (string, []byte) {

	dataStr := strings.SplitN(str, ",", 2) //seperate data:image/png;base64, from the DataURI

	fieldTest := func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	}
	fields := strings.FieldsFunc(dataStr[0], fieldTest) //Fields are: ["data" "image" "png" "base64"]
	dataExt := fields[2]                                //only need the file extension

	if dataExt != fileType {
		err := fmt.Errorf("[Error] file type: %s not allowed", dataExt)
		utils.Check(err)
	}

	data, err := base64.StdEncoding.DecodeString(dataStr[1]) // [] byte
	utils.Check(err)

	return dataExt, data

}

//////////////////////////////////////////////////////////////////////////
//
// Encodes data into a 'data:' URI specified at
// https://developer.mozilla.org/en/data_URIs.
//
//////////////////////////////////////////////////////////////////////////
func dataUrl(data []byte, contentType string) string {
	return fmt.Sprintf("data:%s;base64,%s",
		contentType, base64.StdEncoding.EncodeToString(data))
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func addValidators() {

	//check barcode format is 1 of 3 types
	barcodeFormats := []string{"PKBarcodeFormatQR", "PKBarcodeFormatPDF417", "PKBarcodeFormatAztec"}
	addListValidator("barcode", barcodeFormats)

	//check transit type
	transitTypes := []string{"PKTransitTypeAir", "PKTransitTypeBoat", "PKTransitTypeBus", "PKTransitTypeGeneric", "PKTransitTypeTrain"}
	addListValidator("transit", transitTypes)

	//check datestyle type (timestyle and date style are the same list)
	timeTypes := []string{"PKDateStyleNone", "PKDateStyleShort", "PKDateStyleMedium", "PKDateStyleLong", "PKDateStyleFull"}
	addListValidator("datestyle", timeTypes)

	//check numstyle type
	numTypes := []string{"PKNumberStyleDecimal", "PKNumberStylePercent", "PKNumberStyleScientific", "PKNumberStyleSpellOut"}
	addListValidator("numstyle", numTypes)

	//check text align style types
	textAlignTypes := []string{"PKTextAlignmentLeft", "PKTextAlignmentCenter", "PKTextAlignmentRight", "PKTextAlignmentNatural"}
	addListValidator("align", textAlignTypes)

	//check to make sure its a valid currency code: USD,GBP etc
	govalidator.TagMap["iso4217"] = govalidator.Validator(func(str string) bool {

		if len(str) != 3 {
			return false
		}
		if !govalidator.IsUpperCase(str) {
			return false
		}
		return govalidator.IsAlpha(str)

	})

	//check to make sure its a valid png image datauri
	govalidator.TagMap["imagepng"] = govalidator.Validator(func(str string) bool {

		dataStr := strings.SplitN(str, ",", 2) //seperate data:image/png;base64, from the DataURI

		if !strings.Contains(dataStr[0], "image") {
			return false
		}

		if !strings.Contains(dataStr[0], "png") {
			return false
		}

		return govalidator.IsDataURI(str)

	})

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func addListValidator(key string, typeList []string) {

	govalidator.TagMap[key] = govalidator.Validator(func(str string) bool {
		for _, nextType := range typeList {
			if str == nextType {
				return true
			}
		}
		return false
	})

}

//////////////////////////////////////////////////////////////////////////
//
//	addDb Middleware
//
//
//////////////////////////////////////////////////////////////////////////
func AddDb(c *web.C, h http.Handler) http.Handler {
	handler := func(w http.ResponseWriter, r *http.Request) {

		if c.Env == nil {
			c.Env = make(map[interface{}]interface{})
		}

		if _, ok := c.Env["db"]; !ok { //test is the db is already added

			rt := storer.NewReThink()
			var err error
			rt.Url, err = utils.GetEtcdKey("db/url") //os.Getenv("PASS_APP_DB_URL")
			utils.Check(err)
			rt.Port, err = utils.GetEtcdKey("db/port") //os.Getenv("PASS_APP_DB_PORT")
			utils.Check(err)
			rt.DbName, err = utils.GetEtcdKey("db/name") //os.Getenv("PASS_APP_DB_NAME")
			utils.Check(err)

			s := storer.Storer(rt) //abstract cb to a Storer
			s.Conn()

			c.Env["db"] = s //add db
		}

		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(handler)
}

//////////////////////////////////////////////////////////////////////////
//
//	getDbType
//
//
//////////////////////////////////////////////////////////////////////////
func GetDbType(c web.C) (storer.Storer, error) {

	if v, ok := c.Env["db"]; ok {

		if db, ok := v.(storer.Storer); ok {

			return db, nil //all good

		}
		err := fmt.Errorf("value could not convert to type Storer")
		return nil, err

	}
	err := fmt.Errorf("value for key db, not found")
	return nil, err

}
