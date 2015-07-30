package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"bitbucket.org/cicadaDev/datamodels"
	"bitbucket.org/cicadaDev/storer"
	"bitbucket.org/cicadaDev/utils"
	log "github.com/Sirupsen/logrus"
	"github.com/nullboundary/gocertsigner"
	"github.com/nullboundary/govalidator"
	"github.com/zenazn/goji/web"
)

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func generatePass(dlPass *dataModels.Pass, serialNum string, res http.ResponseWriter, db storer.Storer) {

	//update pass doc
	dlPass.KeyDoc.SerialNumber = serialNum
	err := dlPass.SetPassTypeIdentifier() //passtype sets the identifier
	if err != nil {
		log.Errorf("pass type ID error: %s to db", err.Error())
		return
	}
	dlPass.KeyDoc.TeamIdentifier = "F8QZ9HX5A6" //TODO: set via etcd?
	dlPass.KeyDoc.FormatVersion = 1
	dlPass.KeyDoc.WebServiceURL = webServiceURL
	dlPass.KeyDoc.AuthenticationToken = utils.GenerateToken(tokenPrivateKey, serialNum, dlPass.KeyDoc.PassTypeIdentifier)

	//log pass download info: time, pass id, serialnum, user id.
	var dlLog downloadLog
	dlLog.Id = dlPass.Id
	dlLog.PassType = dlPass.KeyDoc.PassTypeIdentifier
	dlLog.UserId = dlPass.UserId
	dlLog.Downloaded = time.Now()

	err = db.Add("downloadRecord", dlLog)
	if err != nil {
		log.WithField("passid", dlLog.Id).Errorf("error adding pass download record to db %s", err)
		return
	}

	//make manifestdoc map for storing sha1 hashes
	dlPass.ManifestDoc = make(map[string]string)

	//validate the struct before generating a pass
	result, err := govalidator.ValidateStruct(dlPass)
	if err != nil {
		log.Errorf("validated: %t - validation error: %s", result, err.Error())
		http.Error(res, "malformed pass data, cannot build pass", http.StatusInternalServerError)
		return
	}

	modtime := dlPass.Updated
	// Create a new zip archive.
	res.Header().Set("Content-Type", "application/vnd.apple.pkpass") //sets the extension to pkpass
	res.Header().Set("Last-Modified", modtime.UTC().Format(http.TimeFormat))
	//Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w := zip.NewWriter(res)
	defer w.Close()

	//add the pass.json file to the zip pass
	file := addToZipFile(w, "pass.json")
	keyDocBytes, err := json.MarshalIndent(dlPass.KeyDoc, "", "  ") //pretty print json doc
	if err != nil {
		log.WithField("passid", dlPass.Id).Errorf("error marshaling keydoc %s", err)
	}
	file.Write(keyDocBytes)

	//compute sha1 hash for pass.json
	dlPass.ManifestDoc["pass.json"] = fmt.Sprintf("%x", utils.HashSha1Bytes(keyDocBytes))

	//add all images to the pass zip
	for i := range dlPass.Images {

		fileExt, imageBytes := utils.DecodeUriToBytes(dlPass.Images[i].ImageData, "png")
		fileName := dlPass.Images[i].ImageName + "." + fileExt
		file = addToZipFile(w, fileName)
		_, err := file.Write(imageBytes)
		if err != nil {
			log.WithField("image", dlPass.Images[i].ImageName).Errorf("error writing image to zip %s", err)
		}

		//compute sha1 hash for each image file, add to manifest doc
		dlPass.ManifestDoc[fileName] = fmt.Sprintf("%x", utils.HashSha1Bytes(imageBytes))
	}

	//add the manifest.json file to the zip pass
	file = addToZipFile(w, "manifest.json")
	//read in certificates and manifest as bytes
	manifestBytes, err := json.MarshalIndent(dlPass.ManifestDoc, "", "  ")
	if err != nil {
		log.WithField("passid", dlPass.Id).Errorf("error marshaling manifest doc %s", err)
	}
	file.Write(manifestBytes)

	passTypeKey := strings.ToLower(dlPass.PassType) //key map is using lower case only!
	pemKey := keyMap[passTypeKey]                   //get the pem key
	x509cert := certMap[passTypeKey]                //get the cert
	caCert := certMap["AppleWWDRCA"]                //get the ca cert

	//pemKey := goCertSigner.FileToBytes("passCerts/pass.ninja.storecard.key.pem")
	//x509cert := goCertSigner.FileToBytes("passCerts/pass.ninja.storecard.cer")
	signature, err := goCertSigner.SignWithX509PEM(manifestBytes, x509cert, pemKey, pempass, caCert)
	if err != nil {
		log.WithField("passid", dlPass.Id).Errorf("error signing pass %s", err)
	}

	file = addToZipFile(w, "signature")
	_, err = file.Write(signature)
	if err != nil {
		log.WithField("passid", dlPass.Id).Errorf("error adding signature to zip %s", err)
	}

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
	if err != nil {
		log.WithField("header", header.Name).Errorf("error adding zip header %s", err)
	}

	return file

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
			log.WithField("token", authToken).Errorf("error verifying token %s", err)
		}
		return false //verify failed
	}

	return true

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func loadPassKeysCerts(passTypes ...string) {

	for _, passString := range passTypes {
		//create the key & cert path
		passKeyPath := fmt.Sprintf("/certs/passCerts/pass.ninja.%s.key.pem", passString)
		passCertPath := fmt.Sprintf("/certs/passCerts/pass.ninja.%s.cer", passString)
		//load the key & cert
		pemKey := goCertSigner.FileToBytes(passKeyPath)
		x509cert := goCertSigner.FileToBytes(passCertPath)
		//store in maps
		keyMap[passString] = pemKey
		certMap[passString] = x509cert
	}

	//load certificate authority cert.
	caCert := goCertSigner.FileToBytes("/certs/passCerts/AppleWWDRCA.cer")
	//add it to certMap
	certMap["AppleWWDRCA"] = caCert

}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func announceEtcd() {

	sz := len(bindURL)
	servernum := "01"
	if sz > 2 {
		servernum = bindURL[sz-2:]
	}
	///vulcand/backends/b1/servers/srv2 '{"URL": "http://localhost:5001"}'
	utils.HeartBeatEtcd("vulcand/backends/passvendor/servers/svr"+servernum, `{"URL": "`+bindURL+`"}`, 5)
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func addBackNotice(dlPass *dataModels.Pass) error {

	keyDocType, err := dlPass.GetPassStructure()
	if err != nil {
		return err
	}
	msg := &dataModels.Value{ValueString: "This pass was generated by https://pass.ninja for sample viewing and beta testing."}
	notice := dataModels.Fields{Key: "passNinjaNotice", Value: msg}
	keyDocType.BackFields = append(keyDocType.BackFields, notice)

	return nil
}

//////////////////////////////////////////////////////////////////////////
//
//
//
//
//////////////////////////////////////////////////////////////////////////
func limitDownloads(p *dataModels.Pass, passUser *dataModels.UserModel) bool {
	//pass downloads count down from maximum limit

	//limit pass download for freeplan
	if p.PassRemain > 0 && passUser.SubPlan == dataModels.FreePlan {
		return true
	}
	//TODO: small plan should allow less then zero, but charge for it.
	if p.PassRemain > 0 && passUser.SubPlan == dataModels.SmallPlan {
		return true
	}
	//enterprise plans start counting at 0 and count into negative to mean unlimited
	if p.PassRemain <= 0 && passUser.SubPlan == dataModels.EnterprisePlan {
		return true
	}

	return false

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

		if _, ok := c.Env["db"]; !ok { //test is the db is already added

			//connect to db
			rt := storer.NewReThink()

			//load db info from json file
			dbConn, err := utils.GetCryptKey(secretKeyRing, "db/conn")
			if err != nil {
				log.Fatalf("error loading db keys from etcd %s", err)
			}
			var dbMap map[string]interface{}
			err = json.Unmarshal([]byte(dbConn), &dbMap)
			if err != nil {
				log.Fatalf("error unmarshaling db keys from etcd %s", err)
			}

			rt.Url = dbMap["url"].(string)
			rt.Port = dbMap["port"].(string)
			rt.DbName = dbMap["name"].(string)
			rt.AuthKey = dbMap["authKey"].(string)

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
