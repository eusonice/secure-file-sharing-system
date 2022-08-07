package client

import (
	"encoding/json"

	"errors"
	"strconv"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)

/** User struct. */
type User struct {
	Username       string
	Salt           []byte
	SecurePassword []byte
	PEncKey        userlib.PKEEncKey
	PDecKey        userlib.PKEDecKey
	SigKey         userlib.DSSignKey
	VerKey         userlib.DSVerifyKey
	SourceKey      []byte
}

/** File struct. */
type File struct {
	FileOwnerName        string
	FileContentsFirst    userlib.UUID
	FileContentsLast     userlib.UUID
	SharedListCipherText []byte
	SharedListMACTag     []byte
	Count                int
}

/** File pointer struct. Similar to linked list. */
type FilePointer struct {
	NextFile userlib.UUID
	Content  userlib.UUID
	Index    int
}

/** Middle layer pointer struct. A pointer to access actual File. */
type MiddleLayerPointer struct {
	IsOwner           bool
	HashedUsername    []byte
	Filename          string
	FileStructPointer userlib.UUID
}

/** Family pointer struct. A pointer to the shared file. */
type FamilyPointer struct {
	FileStructPointer   userlib.UUID
	EncKey, MACKey      []byte
	FileOwner           string
	DirectRecipientName string
}

/** Invitation struct. */
type Invitation struct {
	PKEFamilyPointerUUID []byte
	SenderSignature      []byte
}

/** Struct for performing authenticated encryption. Guarantees confidentiality and integrity of data. */
type AuthenticatedEncryption struct {
	Ciphertext []byte
	MACtag     []byte
}

/** Creates a new User struct and returns a pointer to it */
func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("Invalid username.")
	}

	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("An error occurred while generating an userUUID.")
	}
	_, ok := userlib.DatastoreGet(userUUID)
	if ok {
		return nil, errors.New("Username already exists.")
	}

	// create a User struct
	var user User
	user.Username = username

	// generate a random salt
	user.Salt = userlib.RandomBytes(16)
	saltUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "salt"))[:16])
	if err != nil {
		return nil, errors.New("An error occurred while generating a saltUUID.")
	}
	userlib.DatastoreSet(saltUUID, user.Salt)
	saltPassword := []byte(password)
	saltPassword = append(saltPassword, user.Salt...)
	user.SecurePassword = userlib.Hash(saltPassword)

	// generate and store public keys
	user.PEncKey, user.PDecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("An error occurred while generating public keys.")
	}
	user.SigKey, user.VerKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("An error occurred while generating signature keys.")
	}

	userlib.KeystoreSet(user.Username+"pke", user.PEncKey)
	userlib.KeystoreSet(user.Username+"ver", user.VerKey)

	// generate and store private keys
	user.SourceKey = userlib.Argon2Key(user.SecurePassword, user.Salt, 16)
	encKey, err := userlib.HashKDF(user.SourceKey, []byte("encryption"))
	if err != nil {
		return nil, errors.New("An error occurred while generating an encryption key.")
	}
	encKey = userlib.Hash(encKey)[:16]
	macKey, err := userlib.HashKDF(user.SourceKey, []byte("mac"))
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC key.")
	}
	macKey = userlib.Hash(macKey)[:16]

	// authenticated encryption on user struct
	var authenticatedUser AuthenticatedEncryption
	marshalizedUser, err := json.Marshal(user)
	if err != nil {
		return nil, errors.New("An error occurred while marshalizing the user struct.")
	}
	authenticatedUser.Ciphertext = userlib.SymEnc(encKey, userlib.RandomBytes(16), marshalizedUser)
	authenticatedUser.MACtag, err = userlib.HMACEval(macKey, authenticatedUser.Ciphertext)
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC tag.")
	}
	marshalizedAuthenticatedUser, err := json.Marshal(authenticatedUser)
	if err != nil {
		return nil, errors.New("An error occurred while marshalizing the authenticated user struct.")
	}
	userlib.DatastoreSet(userUUID, marshalizedAuthenticatedUser)

	return &user, nil
}

/** Obtains the User struct of a user who has already been initialized and returns a pointer to it. */
func GetUser(username string, password string) (userdataptr *User, err error) {
	// check for errors
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("An error occurred while generating an userUUID.")
	}

	// get the user struct
	marshalizedAuthenticatedUser, ok := userlib.DatastoreGet(userUUID)
	if !ok {
		return nil, errors.New("Username doesn't exist.")
	}
	var authenticatedUser AuthenticatedEncryption
	err = json.Unmarshal(marshalizedAuthenticatedUser, &authenticatedUser)
	if err != nil {
		return nil, errors.New("An error occurred while unmarshalizing the authenticated user struct.")
	}

	// get salt
	saltUUID, err := uuid.FromBytes(userlib.Hash([]byte(username + "salt"))[:16])
	if err != nil {
		return nil, errors.New("An error occurred while generating a saltUUID.")
	}
	salt, ok := userlib.DatastoreGet(saltUUID)
	if !ok {
		return nil, errors.New("Salt doesn't exist.")
	}

	// get the secure password
	saltPassword := []byte(password)
	saltPassword = append(saltPassword, salt...)
	securePassword := userlib.Hash(saltPassword)

	sourceKey := userlib.Argon2Key(securePassword, salt, 16)
	encKey, err := userlib.HashKDF(sourceKey, []byte("encryption"))
	if err != nil {
		return nil, errors.New("An error occurred while generating an encryption key.")
	}
	encKey = userlib.Hash(encKey)[:16]
	macKey, err := userlib.HashKDF(sourceKey, []byte("mac"))
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC key.")
	}
	macKey = userlib.Hash(macKey)[:16]

	// verify and decrypt user struct
	macTag, err := userlib.HMACEval(macKey, authenticatedUser.Ciphertext)
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC tag.")
	}
	if !userlib.HMACEqual(macTag, authenticatedUser.MACtag) {
		return nil, errors.New("Cannot verify the MAC tag of the user struct.")
	}

	marshaledUser := userlib.SymDec(encKey, authenticatedUser.Ciphertext)

	var user User
	err = json.Unmarshal(marshaledUser, &user)
	if err != nil {
		return nil, errors.New("An error occurred while unmarshalizing the user struct")
	}

	return &user, nil
}

// Helper function for authenticated encryption using user's sourcekey. */
func (userdata *User) AuthenticatedEncryption(plaintext []byte, encMessage string, macMessage string) (ae AuthenticatedEncryption, err error) {
	// generate keys
	var encryptedObject AuthenticatedEncryption
	encKey, err := userlib.HashKDF(userdata.SourceKey, []byte(encMessage))
	if err != nil {
		return ae, errors.New("An error occured while generating an encryption key.")
	}
	encKey = userlib.Hash(encKey)[:16]
	macKey, err := userlib.HashKDF(userdata.SourceKey, []byte(macMessage))
	if err != nil {
		return ae, errors.New("An error occured while generating a MAC key.")
	}
	macKey = userlib.Hash(macKey)[:16]

	// authenticated encryption on object
	ciphertext := userlib.SymEnc(encKey, userlib.RandomBytes(16), plaintext)
	macTag, err := userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return ae, errors.New("An error occurred while generating a MAC tag.")
	}
	encryptedObject.Ciphertext = ciphertext
	encryptedObject.MACtag = macTag
	return encryptedObject, nil
}

// Helper function for authenticated decryption using user's sourcekey. */
func (userdata *User) AuthenticatedDecryption(ae AuthenticatedEncryption, encMessage string, macMessage string) (plaintext []byte, err error) {
	// generating keys
	encKey, err := userlib.HashKDF(userdata.SourceKey, []byte(encMessage))
	if err != nil {
		return nil, errors.New("An error occured while generating an encryption key.")
	}
	encKey = userlib.Hash(encKey)[:16]
	macKey, err := userlib.HashKDF(userdata.SourceKey, []byte(macMessage))
	if err != nil {
		return nil, errors.New("error occured while generating a MAC key")
	}
	macKey = userlib.Hash(macKey)[:16]

	macTag, err := userlib.HMACEval(macKey, ae.Ciphertext)
	if err != nil {
		return nil, errors.New("error occurred while tagging a ciphertext")
	}
	// verify and decrypt
	if !userlib.HMACEqual(macTag, ae.MACtag) {
		return nil, errors.New("erorr occured while verifying the MAC tag")
	}
	plaintext = userlib.SymDec(encKey, ae.Ciphertext)
	return plaintext, nil
}

/** Persistently stores the given content for future retrieval using the same filename. */
func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	// middle layer pointer
	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return errors.New("error occurred while generating UUID for marshaled MLP struct")
	}
	// check if file with this filename already exists in caller's personal namespace

	marshaledSecureMLPofExistingFile, ok := userlib.DatastoreGet(mlpUUID)

	var fileStruct File
	var secureFileStructUUID userlib.UUID

	var encKey []byte
	var macKey []byte
	if ok { // CASE WHERE FILE ALREADY EXISTS
		// unmarshal the bytes we just got into an MLP
		var aeMLPOfExistingFile AuthenticatedEncryption
		err = json.Unmarshal(marshaledSecureMLPofExistingFile, &aeMLPOfExistingFile)
		if err != nil {
			return errors.New("error occurred while unmarshaling AE of MLP")
		}

		encMessage := "encrypting MLP of " + filename
		macMessage := "tagging MLP of " + filename
		marshaledMLPofExistingFile, err := userdata.AuthenticatedDecryption(aeMLPOfExistingFile, encMessage, macMessage)
		if err != nil {
			return errors.New("error occured while decrypting the existing mlp")
		}
		// unmarshal MLP of existing file
		var mlpOfExistingFile MiddleLayerPointer
		err = json.Unmarshal(marshaledMLPofExistingFile, &mlpOfExistingFile)
		if err != nil {
			return errors.New("error occurred while unmarshaling mlp of existing file")
		}

		var secureFileUUID userlib.UUID

		// BRANCH POINT HERE
		if mlpOfExistingFile.IsOwner {
			// owner case
			secureFileUUID = mlpOfExistingFile.FileStructPointer

			// get keys from AE in datastore
			// get the UUID for the keys
			keyUUIDBytes := userlib.Hash([]byte(filename))
			keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
			keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
			keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
			keyUUID, err := uuid.FromBytes(keyUUIDBytes)
			if err != nil {
				return errors.New("error occurred while generating UUID for keys")
			}
			marshaledAEKeys, ok := userlib.DatastoreGet(keyUUID)
			if !ok {
				return errors.New("error occurred while getting marshaled AE of keys from datastore")
			}
			var aeKeys AuthenticatedEncryption
			err = json.Unmarshal(marshaledAEKeys, &aeKeys)
			if err != nil {

			}
			// verify and decrypt to get keys
			encMessage := "encrypting keys of " + filename
			macMessage := "tagging keys of " + filename

			keyBytes, err := userdata.AuthenticatedDecryption(aeKeys, encMessage, macMessage)
			if err != nil {
				return errors.New("error occured while decrypting the keys !")
			}
			encKey = keyBytes[:16]
			macKey = keyBytes[16:32]
		} else {
			// recipient case
			// get the family pointer
			// set secureFile UUID from family pointer
			secureFamilyPointerUUID := mlpOfExistingFile.FileStructPointer
			marshaledSecureFamilyPointer, ok := userlib.DatastoreGet(secureFamilyPointerUUID)
			if !ok {
				return errors.New("error occurred while getting secure family pointer from datastore 1")
			}

			// unmarshal AE
			var aeFamPointer AuthenticatedEncryption
			err = json.Unmarshal(marshaledSecureFamilyPointer, &aeFamPointer)
			if err != nil {
				return errors.New("error occurred while marshaling family pointer")
			}

			// derive the keys for decrypting family pointer
			famPointerEncKey := userlib.Hash([]byte(string(secureFamilyPointerUUID[:]) + "enc"))[:16]
			famPointerMACKey := userlib.Hash([]byte(string(secureFamilyPointerUUID[:]) + "mac"))[:16]

			// verify
			newMAC, err := userlib.HMACEval(famPointerMACKey, aeFamPointer.Ciphertext)
			if err != nil {
				return errors.New("error occurred while getting new MAC of ciphertext")
			}
			if !userlib.HMACEqual(newMAC, aeFamPointer.MACtag) {
				return errors.New("error occurred while verifying the family pointer struct 1")
			}

			// decrypt
			plaintext := userlib.SymDec(famPointerEncKey, aeFamPointer.Ciphertext)
			var familyPointer FamilyPointer
			err = json.Unmarshal(plaintext, &familyPointer)
			if err != nil {
				return errors.New("error occured while umarshalizing the family pointer")
			}
			encKey = familyPointer.EncKey
			macKey = familyPointer.MACKey
			secureFileUUID = familyPointer.FileStructPointer
		} // we have uuid to the file struct & enc, mac key

		// get file struct from datastore
		secureFileBytes, ok := userlib.DatastoreGet(secureFileUUID)
		if !ok {
			return errors.New("error occurred while retrieving marshaled AE of file struct")
		}
		// unmarshal AE of file struct
		var aeFileStruct AuthenticatedEncryption
		err = json.Unmarshal(secureFileBytes, &aeFileStruct)
		if err != nil {
			return errors.New("error occurred while unmarshaling AE of file struct")
		}

		// use previously retrieved keys to verify-and-decrypt file struct
		newMAC, err := userlib.HMACEval(macKey, aeFileStruct.Ciphertext)
		if err != nil {
			return errors.New("error occurred while creating new MAC tag for ciphertext")
		}

		if !userlib.HMACEqual(newMAC, aeFileStruct.MACtag) {
			return errors.New("error occured while verifying the MAC tag of the file struct")
		}
		marshaledFileStruct := userlib.SymDec(encKey, aeFileStruct.Ciphertext)

		// unmarshal file struct
		err = json.Unmarshal(marshaledFileStruct, &fileStruct)
		if err != nil {
			return errors.New("error occurred while unmarshaling the file struct")
		}
		secureFileStructUUID = secureFileUUID //
		fileStruct.Count = 0                  // hey i just added this
		// got the file struct
	} else { // CASE WHERE FILE DOES NOT EXIST
		// uuid
		/* create a file struct and set its attributes */
		// owner true
		/* if file doesn't exist */
		fileStruct.FileOwnerName = userdata.Username
		fileStruct.Count = 0 // hey i just added this

		// var sharedList []uuid.UUID ///////// *** i changed data structure
		var sharedList map[string]uuid.UUID
		sharedList = make(map[string]uuid.UUID)
		// sharedList = make([]uuid.UUID, 0)

		marshaledSharedList, err := json.Marshal(sharedList)

		sharedListEncKey, err := userlib.HashKDF(userdata.SourceKey, []byte("encrypt key for shared list of "+filename))
		if err != nil {
			return errors.New("error occured while creating an encryption key for shared list")
		}
		sharedListEncKey = userlib.Hash(sharedListEncKey)[:16]

		sharedListMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("mac key for shared list of "+filename))
		if err != nil {
			return errors.New("error occured while creating an mac key for shared list")
		}
		sharedListMACKey = userlib.Hash(sharedListMACKey)[:16]

		fileStruct.SharedListCipherText = userlib.SymEnc(sharedListEncKey, userlib.RandomBytes(16), marshaledSharedList)
		fileStruct.SharedListMACTag, err = userlib.HMACEval(sharedListMACKey, fileStruct.SharedListCipherText)
		secureFileStructUUID = uuid.New()

		/* /////// KEYS //////// */
		/* generate keys, encrypt, tag, and store it in Datastore */

		encKey = userlib.RandomBytes(16)
		macKey = userlib.RandomBytes(16)

		keyBytes := encKey
		keyBytes = append(keyBytes, macKey...)

		var encryptedKeys AuthenticatedEncryption
		encMessage := "encrypting keys of " + filename
		macMessage := "tagging keys of " + filename
		encryptedKeys, err = userdata.AuthenticatedEncryption(keyBytes, encMessage, macMessage)
		if err != nil {
			return errors.New("error occurred while creating authenticated encryption of key concatenation")
		}

		// store keys
		keyUUIDBytes := userlib.Hash([]byte(filename))
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
		keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
		keyUUID, err := uuid.FromBytes(keyUUIDBytes)
		if err != nil {
			return errors.New("error occurred while generating UUID for keys")
		}

		marshalizedEncryptedKeys, err := json.Marshal(encryptedKeys)
		if err != nil {
			return errors.New("error occurred while marshalizing the keys")
		}

		userlib.DatastoreSet(keyUUID, marshalizedEncryptedKeys)

		// create middle layer pointer struct
		var mlp MiddleLayerPointer
		mlp.Filename = filename
		mlp.FileStructPointer = secureFileStructUUID
		mlp.HashedUsername = userlib.Hash([]byte(userdata.Username))
		mlp.IsOwner = true
		// ...

		// marshal the mlp
		marshaledMLP, err := json.Marshal(mlp)
		if err != nil {
			return errors.New("error occurred while marshaling middle layer pointer struct")
		}

		// encrypt the MLP in an AE
		var aeMLP AuthenticatedEncryption
		encMessage = "encrypting MLP of " + filename
		macMessage = "tagging MLP of " + filename
		aeMLP, err = userdata.AuthenticatedEncryption(marshaledMLP, encMessage, macMessage)

		// marshal the AE of MLP
		marshaledAEofMLP, err := json.Marshal(aeMLP)
		if err != nil {
			return errors.New("error occurred while marshaling AE of MLP")
		}

		// create UUID for MLP
		mlpUUIDBytes = userlib.Hash([]byte(filename))
		mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
		mlpUUID, err = uuid.FromBytes(mlpUUIDBytes)
		if err != nil {
			return errors.New("error occurred while generating UUID for marshaled MLP struct")
		}

		// store the middle layer pointer in datastore
		userlib.DatastoreSet(mlpUUID, marshaledAEofMLP)
	}

	// encrypt the content
	// generate helper pointers for file contents
	secureFileContentUUID := uuid.New()
	secureFilePointerUUID := uuid.New()

	/* creating authenticated encryption struct for contents */
	var encryptedContent AuthenticatedEncryption

	// encMessage := "encrypting contents of" + filename
	// macMessage := "tagging contents of" + filename

	contentEncKey := userlib.Hash([]byte(string(secureFilePointerUUID[:]) + "enc"))[:16]
	contentMACKey := userlib.Hash([]byte(string(secureFilePointerUUID[:]) + "mac"))[:16]

	encryptedContent.Ciphertext = userlib.SymEnc(contentEncKey, userlib.RandomBytes(16), content)
	encryptedContent.MACtag, err = userlib.HMACEval(contentMACKey, encryptedContent.Ciphertext)
	if err != nil {
		return errors.New("error occurred while creating MAC for contents")
	}

	marshalizedContent, err := json.Marshal(encryptedContent)
	userlib.DatastoreSet(secureFileContentUUID, marshalizedContent)

	/* create a file pointer struct */
	var filePointer FilePointer
	filePointer.Content = secureFileContentUUID
	filePointer.Index = 0

	/////////////// added new code here
	// marshalize the file pointer s
	filePointerBytes, err := json.Marshal(filePointer)
	if err != nil {
		return errors.New("error occurred while marshaling the file pointer")
	}

	// encrypt the file pointer with keys generated from file struct UUID and file pointer
	filePointerEncKey := userlib.Hash([]byte(string(secureFileStructUUID[:]) + "enc" + strconv.Itoa(fileStruct.Count)))[:16]
	filePointerMACKey := userlib.Hash([]byte(string(secureFileStructUUID[:]) + "mac" + strconv.Itoa(fileStruct.Count)))[:16]

	var aeFilePointer AuthenticatedEncryption
	aeFilePointer.Ciphertext = userlib.SymEnc(filePointerEncKey, userlib.RandomBytes(16), filePointerBytes)
	aeFilePointer.MACtag, err = userlib.HMACEval(filePointerMACKey, aeFilePointer.Ciphertext)
	if err != nil {
		return errors.New("error occured while generating a MAC tag for ae file pointer")
	}

	// marshal the AE of file pointer
	aeFilePointerBytes, err := json.Marshal(aeFilePointer)
	if err != nil {
		return errors.New("error occurred while marshaling")
	}
	/* store file pointer struct in datastore */
	userlib.DatastoreSet(secureFilePointerUUID, aeFilePointerBytes)

	// add content to file
	fileStruct.FileContentsFirst = secureFilePointerUUID
	fileStruct.FileContentsLast = secureFilePointerUUID
	fileStruct.Count = 1

	// marshal the file struct
	fileStructBytes, err := json.Marshal(fileStruct)
	if err != nil {
		return errors.New("error occurred while marshalizing the file struct")
	}

	// encrypt and store file struct
	var autEncFileStruct AuthenticatedEncryption
	autEncFileStruct.Ciphertext = userlib.SymEnc(encKey, userlib.RandomBytes(16), fileStructBytes)
	autEncFileStruct.MACtag, err = userlib.HMACEval(macKey, autEncFileStruct.Ciphertext)
	if err != nil {
		return errors.New("error occurred while tagging the file struct bytes")
	}

	secureFileStructBytes, err := json.Marshal(autEncFileStruct)
	if err != nil {
		return errors.New("error occurred while marshaling the authenticated encryption of the file struct")
	}

	// generate random UUID for this secure file struct's bytes
	userlib.DatastoreSet(secureFileStructUUID, secureFileStructBytes)

	// store symkeys used for decrypting this file, using autenc
	// concatenate the keys??? which are byte slices???

	// var autEncSymKeys AuthenticatedEncryption
	// autEncSymKeys.Ciphertext =

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	// access middle layer pointer

	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return errors.New("file does not exist in user's personal namespace")
	}

	// get the AE of MLP from datastore
	aeMLPBytes, ok := userlib.DatastoreGet(mlpUUID)
	if !ok {
		return errors.New("error occurred while retrieving marshaled MLP bytes 2")
	}

	// unmarshal the MLP to find the file struct UUID
	var aeMLP AuthenticatedEncryption
	err = json.Unmarshal(aeMLPBytes, &aeMLP)
	if err != nil {
		return errors.New("error occurred while unmarshaling ae MLP")
	}

	// verify and decrypt the damn MLP
	encMessage := "encrypting MLP of " + filename
	macMessage := "tagging MLP of " + filename
	mlpBytes, err := userdata.AuthenticatedDecryption(aeMLP, encMessage, macMessage)
	if err != nil {
		return errors.New("error occurred while verify-and-decrypting AE of MLP 1")
	}
	// initialize MLP struct
	var mlpStruct MiddleLayerPointer
	err = json.Unmarshal(mlpBytes, &mlpStruct)
	if err != nil {
		return errors.New("error occurred while unmarshaling MLP struct")
	}

	var secureFileUUID userlib.UUID
	var encKey []byte
	var macKey []byte
	// BEHAVIOR BRANCHES HERE: OWNER WILL DIRECTLY GET FILE STRUCT UUID, BUT RECIPIENTS WILL GET FAMILY POINTER
	if mlpStruct.IsOwner {
		// owner case
		secureFileUUID = mlpStruct.FileStructPointer

		keyUUIDBytes := userlib.Hash([]byte(filename))
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
		keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
		keyUUID, err := uuid.FromBytes(keyUUIDBytes)
		if err != nil {
			return errors.New("error occurred while generating UUID for keys")
		}

		// use keyUUID to get the marshaled key struct from datastore
		keyBytes, ok := userlib.DatastoreGet(keyUUID)
		if !ok {
			return errors.New("error occurred while getting encrypted keys from datastore")
		}

		// return errors.New(string(keyBytes)) // marshalized encrypted key struct

		// unmarshal the encrypted key struct
		var autEncKeyStruct AuthenticatedEncryption
		err = json.Unmarshal(keyBytes, &autEncKeyStruct)
		if err != nil {
			return errors.New("error occurred while unmarshaling the key authenticatedencryption struct")
		}

		encMessage := "encrypting keys of " + filename
		macMessage := "tagging keys of " + filename

		concatenatedKeys, err := userdata.AuthenticatedDecryption(autEncKeyStruct, encMessage, macMessage)
		if err != nil {
			return err // ors.New("error occured while decrypting the keys")
		}
		encKey = concatenatedKeys[:16]
		macKey = concatenatedKeys[16:32]

	} else {
		// recipient case
		// get the family pointer
		// set secureFile UUID from family pointer
		secureFamilyPointerUUID := mlpStruct.FileStructPointer
		marshaledSecureFamilyPointer, ok := userlib.DatastoreGet(secureFamilyPointerUUID)
		if !ok {
			return errors.New("error occurred while getting secure family pointer from datastore 2")
		}

		// unmarshal AE
		var aeFamPointer AuthenticatedEncryption
		err = json.Unmarshal(marshaledSecureFamilyPointer, &aeFamPointer)
		if err != nil {
			return errors.New("error occurred while marshaling family pointer")
		}

		// derive the keys for family pointer decryption
		famPointerEncKey := userlib.Hash([]byte(string(secureFamilyPointerUUID[:]) + "enc"))[:16]
		famPointerMACKey := userlib.Hash([]byte(string(secureFamilyPointerUUID[:]) + "mac"))[:16]

		// verify
		newMAC, err := userlib.HMACEval(famPointerMACKey, aeFamPointer.Ciphertext)
		if err != nil {
			return errors.New("error occurred while getting new MAC of ciphertext")
		}
		if !userlib.HMACEqual(newMAC, aeFamPointer.MACtag) {
			return errors.New("error occurred while verifying the family pointer struct 2")
		}

		// decrypt
		plaintext := userlib.SymDec(famPointerEncKey, aeFamPointer.Ciphertext)
		var familyPointer FamilyPointer
		err = json.Unmarshal(plaintext, &familyPointer)
		if err != nil {
			return errors.New("error occured while umarshalizing the family pointer")
		}
		secureFileUUID = familyPointer.FileStructPointer
		encKey = familyPointer.EncKey
		macKey = familyPointer.MACKey
	}

	secureFileBytes, ok := userlib.DatastoreGet(secureFileUUID)

	var autEncFileStruct AuthenticatedEncryption
	err = json.Unmarshal(secureFileBytes, &autEncFileStruct)
	if err != nil {
		return errors.New("error occurred while unmarshaling file's authenticated encryption struct 1")
	}

	// verify the file struct
	fileStructMACTag, err := userlib.HMACEval(macKey, autEncFileStruct.Ciphertext)
	if err != nil {
		return errors.New("error occurred while calculating tag of encrypted file struct")
	}

	if !(userlib.HMACEqual(fileStructMACTag, autEncFileStruct.MACtag)) {
		return errors.New("error occured while verifying the file struct")
	}

	// decrypt the file struct
	marshaledFileStruct := userlib.SymDec(encKey, autEncFileStruct.Ciphertext)

	// unmarshal the file struct's bytes
	var fileStruct File
	err = json.Unmarshal(marshaledFileStruct, &fileStruct)
	if err != nil {
		return errors.New("error occured while unmarshalizing the file struct 1")
	}

	// AT THIS POINT, we have the file struct!!!

	// encrypt-and-MAC the new content
	// create UUIDs to use for encryption
	filePointerUUID := uuid.New()
	fileContentUUID := uuid.New()

	contentEncKey := userlib.Hash([]byte(string(filePointerUUID[:]) + "enc"))[:16]
	contentMACKey := userlib.Hash([]byte(string(filePointerUUID[:]) + "mac"))[:16]

	var encryptedContent AuthenticatedEncryption
	encryptedContent.Ciphertext = userlib.SymEnc(contentEncKey, userlib.RandomBytes(16), content)
	encryptedContent.MACtag, err = userlib.HMACEval(contentMACKey, encryptedContent.Ciphertext)
	if err != nil {
		return errors.New("error occurred while creating MAC for contents")
	}

	marshalizedContent, err := json.Marshal(encryptedContent)
	userlib.DatastoreSet(fileContentUUID, marshalizedContent)

	/* create a file pointer struct */
	var filePointer FilePointer
	filePointer.Content = fileContentUUID
	filePointer.Index = fileStruct.Count

	// marshal file pointer
	filePointerBytes, err := json.Marshal(filePointer)
	if err != nil {
		return errors.New("error occurred while marshaling new file pointer")
	}

	// encrypt the file pointer with keys generated from file struct UUID and file pointer
	filePointerEncKey := userlib.Hash([]byte(string(secureFileUUID[:]) + "enc" + strconv.Itoa(fileStruct.Count)))[:16]
	filePointerMACKey := userlib.Hash([]byte(string(secureFileUUID[:]) + "mac" + strconv.Itoa(fileStruct.Count)))[:16]

	var aeFilePointer AuthenticatedEncryption
	aeFilePointer.Ciphertext = userlib.SymEnc(filePointerEncKey, userlib.RandomBytes(16), filePointerBytes)
	aeFilePointer.MACtag, err = userlib.HMACEval(filePointerMACKey, aeFilePointer.Ciphertext)
	if err != nil {
		return errors.New("error occured while generating a MAC tag for ae file pointer")
	}

	// marshal the AE of file pointer
	aeFilePointerBytes, err := json.Marshal(aeFilePointer)
	if err != nil {
		return errors.New("error occurred while marshaling")
	}
	/* store file pointer struct in datastore */
	userlib.DatastoreSet(filePointerUUID, aeFilePointerBytes)

	// update the current last pointer's next, first get AE
	aeOldLastPointerBytes, ok := userlib.DatastoreGet(fileStruct.FileContentsLast)
	if !ok {
		return errors.New("error occurred while retrieving current last pointer from datastore")
	}

	var aeOldLastPointer AuthenticatedEncryption
	err = json.Unmarshal(aeOldLastPointerBytes, &aeOldLastPointer)
	if err != nil {
		return errors.New("error occured while unmarshalizing the old ae last pointer")
	}

	// decrypt AE of old last filepointer
	oldLastFilePointerEncKey := userlib.Hash([]byte(string(secureFileUUID[:]) + "enc" + strconv.Itoa(fileStruct.Count-1)))[:16]
	oldLastFilePointerMACKey := userlib.Hash([]byte(string(secureFileUUID[:]) + "mac" + strconv.Itoa(fileStruct.Count-1)))[:16]

	// verify
	newMAC, err := userlib.HMACEval(oldLastFilePointerMACKey, aeOldLastPointer.Ciphertext)
	if err != nil {
		return errors.New("error occured while creating mac tag of aeoldlastpointer")
	}
	if !userlib.HMACEqual(newMAC, aeOldLastPointer.MACtag) {
		return errors.New("error occured while verifying the mac tag of aeoldlastpointer")
	}
	oldLastPointerBytes := userlib.SymDec(oldLastFilePointerEncKey, aeOldLastPointer.Ciphertext)

	var oldLastPointer FilePointer
	err = json.Unmarshal(oldLastPointerBytes, &oldLastPointer)
	if err != nil {
		return errors.New("error occurred while unmarshaling the file struct's old last pointer")
	}

	// THE CHANGE
	oldLastPointer.NextFile = filePointerUUID

	// re-marshal old last pointer
	oldLastPointerBytes, err = json.Marshal(oldLastPointer)
	if err != nil {
		return errors.New("error occurred while marshaling file struct's old last pointer")
	}

	// begin re-encryption
	aeOldLastPointer.Ciphertext = userlib.SymEnc(oldLastFilePointerEncKey, userlib.RandomBytes(16), oldLastPointerBytes)
	aeOldLastPointer.MACtag, err = userlib.HMACEval(oldLastFilePointerMACKey, aeOldLastPointer.Ciphertext)
	if err != nil {
		return errors.New("error occurred while creating MAC for old last pointer")
	}

	// marshal and store the pointer back (to update changes)
	aeOldLastPointerBytes, err = json.Marshal(aeOldLastPointer)
	if err != nil {
		return errors.New("error occurred while remarshaling the file's previous last pointer")
	}
	userlib.DatastoreSet(fileStruct.FileContentsLast, aeOldLastPointerBytes)

	// increment file struct block count
	fileStruct.Count += 1

	// update the file struct's last
	fileStruct.FileContentsLast = filePointerUUID

	// marshal encrypt whatever to file struct
	fileStructBytes, err := json.Marshal(fileStruct)
	if err != nil {
		return errors.New("error occurred while marshalizing the file struct")
	}

	var encryptNewFileStruct AuthenticatedEncryption
	encryptNewFileStruct.Ciphertext = userlib.SymEnc(encKey, userlib.RandomBytes(16), fileStructBytes)
	encryptNewFileStruct.MACtag, err = userlib.HMACEval(macKey, encryptNewFileStruct.Ciphertext)
	if err != nil {
		return errors.New("error occurred while generating a MAC tag")
	}

	encryptNewFileStructBytes, err := json.Marshal(encryptNewFileStruct)
	if err != nil {
		return errors.New("error occurred while marshalizing the new file struct")
	}

	userlib.DatastoreSet(secureFileUUID, encryptNewFileStructBytes)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// access middle layer pointer

	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return nil, errors.New("file does not exist in user's personal namespace")
	}

	// get the AE of MLP from datastore
	aeMLPBytes, ok := userlib.DatastoreGet(mlpUUID)
	if !ok {
		return nil, errors.New("error occurred while retrieving marshaled MLP bytes 1")
	}

	// unmarshal the MLP to find the file struct UUID
	var aeMLP AuthenticatedEncryption
	err = json.Unmarshal(aeMLPBytes, &aeMLP)
	if err != nil {
		return nil, errors.New("error occurred while unmarshaling ae MLP")
	}

	// verify and decrypt the damn MLP
	encMessage := "encrypting MLP of " + filename
	macMessage := "tagging MLP of " + filename
	mlpBytes, err := userdata.AuthenticatedDecryption(aeMLP, encMessage, macMessage)
	if err != nil {
		return nil, errors.New("error occurred while verify-and-decrypting AE of MLP 2")
	}

	// initialize MLP struct
	var mlpStruct MiddleLayerPointer
	err = json.Unmarshal(mlpBytes, &mlpStruct)
	if err != nil {
		return nil, errors.New("error occurred while unmarshaling MLP struct")
	}

	// BEHAVIOR BRANCHES HERE: OWNER WILL DIRECTLY GET FILE STRUCT UUID, BUT RECIPIENTS WILL GET FAMILY POINTER
	var secureFileUUID userlib.UUID
	var encKey []byte
	var macKey []byte
	if mlpStruct.IsOwner {
		// owner case
		secureFileUUID = mlpStruct.FileStructPointer
		/* /////// KEY STUFF ////////// */
		keyUUIDBytes := userlib.Hash([]byte(filename))
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
		keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
		keyUUID, err := uuid.FromBytes(keyUUIDBytes)
		if err != nil {
			return nil, errors.New("error occurred while generating UUID for keys")
		}

		// use keyUUID to get the marshaled key struct from datastore
		keyBytes, ok := userlib.DatastoreGet(keyUUID)
		if !ok {
			return nil, errors.New("error occurred while getting encrypted keys from datastore")
		}

		// unmarshal the encrypted key struct
		var autEncKeyStruct AuthenticatedEncryption
		err = json.Unmarshal(keyBytes, &autEncKeyStruct)
		if err != nil {
			return nil, errors.New("error occurred while unmarshaling the key authenticatedencryption struct")
		}

		// regenerate keys to verify and decrypt the keys for the file struct
		encKeyKey, err := userlib.HashKDF(userdata.SourceKey, []byte("encrypting keys of "+filename))
		if err != nil {
			return nil, errors.New("error occurred while generating an encryption key for keys")
		}
		encKeyKey = userlib.Hash(encKeyKey)[:16]
		macKeyKey, err := userlib.HashKDF(userdata.SourceKey, []byte("tagging keys of "+filename))
		if err != nil {
			return nil, errors.New("error occurred while generating a MAC key for keys")
		}
		macKeyKey = userlib.Hash(macKeyKey)[:16]

		// verify the secure key struct
		keyMACTag, err := userlib.HMACEval(macKeyKey, autEncKeyStruct.Ciphertext)
		if err != nil {
			return nil, errors.New("error occurred while generating a MAC tag")
		}

		if !(userlib.HMACEqual(keyMACTag, autEncKeyStruct.MACtag)) {
			return nil, errors.New("error occurred while verifying keys 1")
		}

		// decrypt to get the two keys concatenated together; slice them
		concatenatedKeys := userlib.SymDec(encKeyKey, autEncKeyStruct.Ciphertext)
		encKey = concatenatedKeys[:16]
		macKey = concatenatedKeys[16:32]
	} else {
		// recipient case
		// get the family pointer
		// set secureFile UUID from family pointer
		secureFamilyPointerUUID := mlpStruct.FileStructPointer
		marshaledSecureFamilyPointer, ok := userlib.DatastoreGet(secureFamilyPointerUUID)
		if !ok {
			return nil, errors.New("error occurred while getting secure family pointer from datastore 3")
		}

		// unmarshal AE
		var aeFamPointer AuthenticatedEncryption
		err = json.Unmarshal(marshaledSecureFamilyPointer, &aeFamPointer)
		if err != nil {
			return nil, errors.New("error occurred while marshaling family pointer")
		}

		// derive the keys for family pointer
		famPointerEncKey := userlib.Hash([]byte(string(secureFamilyPointerUUID[:]) + "enc"))[:16]
		famPointerMACKey := userlib.Hash([]byte(string(secureFamilyPointerUUID[:]) + "mac"))[:16]

		// verify
		newMAC, err := userlib.HMACEval(famPointerMACKey, aeFamPointer.Ciphertext)
		if err != nil {
			return nil, errors.New("error occurred while getting new MAC of ciphertext")
		}
		if !userlib.HMACEqual(newMAC, aeFamPointer.MACtag) {
			return nil, errors.New("error occurred while verifying the family pointer struct 3")
		}

		// decrypt
		plaintext := userlib.SymDec(famPointerEncKey, aeFamPointer.Ciphertext)
		var familyPointer FamilyPointer
		err = json.Unmarshal(plaintext, &familyPointer)
		if err != nil {
			return nil, errors.New("error occured while umarshalizing the family pointer")
		}
		secureFileUUID = familyPointer.FileStructPointer
		encKey = familyPointer.EncKey
		macKey = familyPointer.MACKey
	}
	// after this we have file struct UUID=secureFileUUID
	// we have keys for file struct which are encKey and macKey
	// get file struct UUID from the MLP
	// secureFileUUID := mlpStruct.FileStructPointer
	secureFileBytes, ok := userlib.DatastoreGet(secureFileUUID)

	var autEncFileStruct AuthenticatedEncryption
	err = json.Unmarshal(secureFileBytes, &autEncFileStruct)
	if err != nil {
		return nil, errors.New("error occurred while unmarshaling file's authenticated encryption struct 2")
	}

	// verify the file struct
	fileStructMACTag, err := userlib.HMACEval(macKey, autEncFileStruct.Ciphertext)
	if err != nil {
		return nil, errors.New("error occurred while calculating tag of encrypted file struct")
	}

	if !(userlib.HMACEqual(fileStructMACTag, autEncFileStruct.MACtag)) {
		return nil, errors.New("error occured while verifying the file struct")
	}

	// decrypt the file struct
	marshaledFileStruct := userlib.SymDec(encKey, autEncFileStruct.Ciphertext)

	// unmarshal the file struct's bytes
	var fileStruct File
	err = json.Unmarshal(marshaledFileStruct, &fileStruct)
	if err != nil {
		return nil, errors.New("error occured while unmarshalizing the file struct 2")
	}

	// AT THIS POINT, we have the file struct!!!
	lastFilePointer := fileStruct.FileContentsLast
	currentFilePointer := fileStruct.FileContentsFirst
	count := 0
	exit := false
	for !exit {

		marshaledAEFilePointer, ok := userlib.DatastoreGet(currentFilePointer)
		if !ok {
			return nil, errors.New("error occurred while retrieving AE of file pointer number " + strconv.Itoa(count))
		}

		var aeFilePointer AuthenticatedEncryption
		err = json.Unmarshal(marshaledAEFilePointer, &aeFilePointer)
		if err != nil {
			return nil, errors.New("error occurred while unmarshaling AE of file pointer number " + strconv.Itoa(count))
		}

		filePointerEncKey := userlib.Hash([]byte(string(secureFileUUID[:]) + "enc" + strconv.Itoa(count)))[:16]
		filePointerMACKey := userlib.Hash([]byte(string(secureFileUUID[:]) + "mac" + strconv.Itoa(count)))[:16]

		newMAC, err := userlib.HMACEval(filePointerMACKey, aeFilePointer.Ciphertext)
		if err != nil {
			return nil, errors.New("error occured while creating mac tag of file pointer number " + strconv.Itoa(count))
		}

		// verify
		if !userlib.HMACEqual(newMAC, aeFilePointer.MACtag) {
			return nil, errors.New("error occurred while verifying MAC of file pointer " + strconv.Itoa(count))
		}

		// decrypt
		marshaledFilePointer := userlib.SymDec(filePointerEncKey, aeFilePointer.Ciphertext)

		// unmarshal the file pointer struct to retrieve the content UUID attribute
		var filePointer FilePointer
		err = json.Unmarshal(marshaledFilePointer, &filePointer)
		if err != nil {
			return nil, errors.New("error occured while unmarshalizing the file pointer " + strconv.Itoa(count))
		}

		// get content keys

		// get the content pointer
		marshaledSecureContents, ok := userlib.DatastoreGet(filePointer.Content)
		// unmarshal the authenticated encryption of the contents struct
		var aeContent AuthenticatedEncryption
		err = json.Unmarshal(marshaledSecureContents, &aeContent)
		if err != nil {
			return nil, errors.New("error occurred while unmarshalizing the file content " + strconv.Itoa(count))
		}

		contentEncKey := userlib.Hash([]byte(string(currentFilePointer[:]) + "enc"))[:16]
		contentMACKey := userlib.Hash([]byte(string(currentFilePointer[:]) + "mac"))[:16]

		newMAC, err = userlib.HMACEval(contentMACKey, aeContent.Ciphertext)
		if err != nil {
			return nil, errors.New("error occurred while getting the MAC of file content " + strconv.Itoa(count))
		}
		// verify
		if !userlib.HMACEqual(newMAC, aeContent.MACtag) {
			return nil, errors.New("error occured while verifying the MAC of file content " + strconv.Itoa(count))
		}

		returnedContentBytes := userlib.SymDec(contentEncKey, aeContent.Ciphertext)

		content = append(content, returnedContentBytes...)

		if currentFilePointer == lastFilePointer {
			exit = true
		}

		count += 1
		currentFilePointer = filePointer.NextFile
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// get UUID for MLP
	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return uuid.Nil, errors.New("error occurred while generating UUID for marshaled MLP struct")
	}

	// get MLP from datastore
	aeMLPBytes, ok := userlib.DatastoreGet(mlpUUID)
	if !ok {
		return uuid.Nil, errors.New("error occured while retrieving the MLP")
	}

	// unmarshal AE of MLP
	var aeMLP AuthenticatedEncryption
	err = json.Unmarshal(aeMLPBytes, &aeMLP)
	if err != nil {
		return uuid.Nil, errors.New("error occurred while unmarshaling AE of MLP")
	}

	encMessage := "encrypting MLP of " + filename
	macMessage := "tagging MLP of " + filename
	mlpBytes, err := userdata.AuthenticatedDecryption(aeMLP, encMessage, macMessage)
	if err != nil {
		return uuid.Nil, errors.New("error occurred while decrypting aemlp in create invitation")
	}

	var mlpStruct MiddleLayerPointer
	err = json.Unmarshal(mlpBytes, &mlpStruct)
	if err != nil {
		return uuid.Nil, errors.New("error occured while unmarshalizing the mlp struct")
	}

	var famPointerUUID userlib.UUID
	if mlpStruct.IsOwner {
		// put family pointer uuid in invitation (encrypted with PKE)
		// sign the encryption
		// store invitation struct in DS, return UUID to it

		// get file struct's keys
		keyUUIDBytes := userlib.Hash([]byte(filename))
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
		keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
		keyUUID, err := uuid.FromBytes(keyUUIDBytes)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while generating UUID for keys")
		}

		var encryptedKeys AuthenticatedEncryption
		encryptedKeysBytes, ok := userlib.DatastoreGet(keyUUID)
		if !ok {
			return uuid.Nil, errors.New("error occured while retrieving the key struct")
		}

		err = json.Unmarshal(encryptedKeysBytes, &encryptedKeys)
		if err != nil {
			return uuid.Nil, errors.New("error occured while unmarshalizing the key struct")
		}

		encMessage = "encrypting keys of " + filename
		macMessage = "tagging keys of " + filename
		concatenatedKeys, err := userdata.AuthenticatedDecryption(encryptedKeys, encMessage, macMessage)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while verifying-and-decrypting AE of keys")
		}
		encKey := concatenatedKeys[:16]
		macKey := concatenatedKeys[16:32]

		// get file struct uuid from mlp
		// get file struct pointer
		fileStructPointer := mlpStruct.FileStructPointer

		// verify-and-decrypt it
		marshaledAEFileStruct, ok := userlib.DatastoreGet(fileStructPointer)
		if !ok {
			return uuid.Nil, errors.New("error occurred while retrieving marshaled AE of file struct from DS")
		}

		// unmarshal the AE of file struct
		var aeFileStruct AuthenticatedEncryption
		err = json.Unmarshal(marshaledAEFileStruct, &aeFileStruct)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while unmarshaling the AE of file struct")
		}

		// get new MAC
		newMAC, err := userlib.HMACEval(macKey, aeFileStruct.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while getting new MAC of ciphertet")
		}

		// verify
		if !userlib.HMACEqual(newMAC, aeFileStruct.MACtag) {
			return uuid.Nil, errors.New("error occurred while verifying the file struct")
		}

		// decrypt
		fileStructBytes := userlib.SymDec(encKey, aeFileStruct.Ciphertext)

		var fileStruct File
		err = json.Unmarshal(fileStructBytes, &fileStruct)
		if err != nil {
			return uuid.Nil, errors.New("error occured while unmarshalizing the file struct 3")
		}

		// create family pointer
		var famPointer FamilyPointer
		famPointer.FileStructPointer = fileStructPointer
		famPointer.EncKey = encKey
		famPointer.MACKey = macKey
		famPointer.FileOwner = userdata.Username
		famPointer.DirectRecipientName = recipientUsername

		famPointerUUID = uuid.New()

		famPointerEncKey := userlib.Hash([]byte(string(famPointerUUID[:]) + "enc"))[:16]
		famPointerMACKey := userlib.Hash([]byte(string(famPointerUUID[:]) + "mac"))[:16]

		marshaledFamPointer, err := json.Marshal(famPointer)
		if err != nil {
			return uuid.Nil, errors.New("error occured while marshalizing the fampointer")
		}

		var aeFamPointer AuthenticatedEncryption
		aeFamPointer.Ciphertext = userlib.SymEnc(famPointerEncKey, userlib.RandomBytes(16), marshaledFamPointer)
		aeFamPointer.MACtag, err = userlib.HMACEval(famPointerMACKey, aeFamPointer.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while creating MAC tag for AE of fam pointer")
		}

		// marshal ae fam pointer
		marshaledAEFamPointer, err := json.Marshal(aeFamPointer)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while marshaling ae of fam pointer")
		}
		userlib.DatastoreSet(famPointerUUID, marshaledAEFamPointer)

		// append to share list
		sharedListEncKey, err := userlib.HashKDF(userdata.SourceKey, []byte("encrypt key for shared list of "+filename))
		if err != nil {
			return uuid.Nil, errors.New("error occurred while creating an encryption key for shared list")
		}
		sharedListEncKey = userlib.Hash(sharedListEncKey)[:16]
		sharedListMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("mac key for shared list of "+filename))
		if err != nil {
			return uuid.Nil, errors.New("error occurred while creating a mac key for shared list")
		}
		sharedListMACKey = userlib.Hash(sharedListMACKey)[:16]
		sharedListMACTag, err := userlib.HMACEval(sharedListMACKey, fileStruct.SharedListCipherText)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while creating a mac tag for shared list")
		}
		if !userlib.HMACEqual(sharedListMACTag, fileStruct.SharedListMACTag) {
			return uuid.Nil, errors.New("error occurred while verifying the MAC tag for shared list")
		}

		marshalizedSharedList := userlib.SymDec(sharedListEncKey, fileStruct.SharedListCipherText)
		var sharedList map[string]userlib.UUID
		// var sharedList []uuid.UUID *** i changed data structure
		err = json.Unmarshal(marshalizedSharedList, &sharedList)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while unmarshalizing marshalizedsharedlist")
		}
		// sharedList = append(sharedList, famPointerUUID) *** i changed data structure
		sharedList[recipientUsername] = famPointerUUID
		updatedMarshalizedSharedList, err := json.Marshal(sharedList)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while marshalizing the updated shared list")
		}
		// encrypt and MAC
		fileStruct.SharedListCipherText = userlib.SymEnc(sharedListEncKey, userlib.RandomBytes(16), updatedMarshalizedSharedList)
		fileStruct.SharedListMACTag, err = userlib.HMACEval(sharedListMACKey, fileStruct.SharedListCipherText)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while generating a MAC tag for shared list")
		}

		// re-marshal the file struct
		marshaledFileStruct, err := json.Marshal(fileStruct)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while marshaling the file struct")
		}

		// re-encrypt the file struct
		var encryptedFileStruct AuthenticatedEncryption
		encryptedFileStruct.Ciphertext = userlib.SymEnc(encKey, userlib.RandomBytes(16), marshaledFileStruct)
		encryptedFileStruct.MACtag, err = userlib.HMACEval(macKey, encryptedFileStruct.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while re-encrypting file struct")
		}

		// re-marshal the AE of file struct
		marshaledEncryptedFileStruct, err := json.Marshal(encryptedFileStruct)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while marshaling the AE of file struct")
		}
		userlib.DatastoreSet(fileStructPointer, marshaledEncryptedFileStruct)
	} else {
		// get family pointer uuid
		famPointerUUID = mlpStruct.FileStructPointer

		// verify that family pointer has not been tampered with //
		aeFamPointerBytes, ok := userlib.DatastoreGet(famPointerUUID)
		if !ok {
			return uuid.Nil, errors.New("error occurred while retrieving marshaled ae of fam pointer")
		}

		// unmarshal to get AE
		var aeFamPointer AuthenticatedEncryption
		err = json.Unmarshal(aeFamPointerBytes, &aeFamPointer)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while unmarshaling ae of fam pointer")
		}

		// get keys
		famPointerEncKey := userlib.Hash([]byte(string(famPointerUUID[:]) + "enc"))[:16]
		famPointerMACKey := userlib.Hash([]byte(string(famPointerUUID[:]) + "mac"))[:16]

		// get newMAC
		newMAC, err := userlib.HMACEval(famPointerMACKey, aeFamPointer.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("error occurred while creating new MAC for ae of fam pointer")
		}

		// verify
		if !userlib.HMACEqual(newMAC, aeFamPointer.MACtag) {
			return uuid.Nil, errors.New("error occurred while verifying MAC of ae of fam pointer")
		}

		famPointerBytes := userlib.SymDec(famPointerEncKey, aeFamPointer.Ciphertext)
		var famPointer FamilyPointer
		err = json.Unmarshal(famPointerBytes, &famPointer)
		if err != nil {
			return uuid.Nil, errors.New("error occured while unmarshalizing family pointer bytes")
		}

		fileStructUUID := famPointer.FileStructPointer
		marshaledAEFileStruct, ok := userlib.DatastoreGet(fileStructUUID)
		if !ok {
			return uuid.Nil, errors.New("error occured while getting ae file struct")
		}

		var aeFileStruct AuthenticatedEncryption
		err = json.Unmarshal(marshaledAEFileStruct, &aeFileStruct)
		if err != nil {
			return uuid.Nil, errors.New("error occured while unmarshalizing file struct")
		}

		fileStructMACTag, err := userlib.HMACEval(famPointer.MACKey, aeFileStruct.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("error occured while generating a mac tag")
		}

		if !userlib.HMACEqual(fileStructMACTag, aeFileStruct.MACtag) {
			return uuid.Nil, errors.New("error occured while verifying the file struct that it's not tampered")
		}

		// create invitation struct
		// put family pointer uuid in invitation struct encrypted with pke
		// sign the encryption
		// store invitaion struct in ds return uuid to it
	}

	// decrypt ciphertext to get marshaled uuid slice/array
	// unmarshal the slice/array
	// append to the array
	// marshal and encrypt again

	var invitation Invitation
	recipientPubKey, ok := userlib.KeystoreGet(recipientUsername + "pke")
	if !ok {
		return uuid.Nil, errors.New("error occured while retrieving the recipient's public key")
	}

	// marshal fam pointer UUID so we can do PKE on it
	marshaledFamPointerUUID, err := json.Marshal(famPointerUUID)
	if err != nil {
		return uuid.Nil, errors.New("error occurred while marshaling the UUID of fam pointer")
	}

	// do PKE on marshal fam pointer, with recipient's public key
	invitation.PKEFamilyPointerUUID, err = userlib.PKEEnc(recipientPubKey, marshaledFamPointerUUID)
	if err != nil {
		return uuid.Nil, errors.New("error occured while encrypting the family pointer with the recipient's public key")
	}

	// sign it with sender's signing key
	invitation.SenderSignature, err = userlib.DSSign(userdata.SigKey, invitation.PKEFamilyPointerUUID)
	if err != nil {
		return uuid.Nil, errors.New("error occured while creating a digital signature on the family pointer")
	}

	// marshal
	marshalizedInvitation, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, errors.New("error occured while marshalizing the invitation")
	}

	// store in datastore with new uuid
	invitationUUID := uuid.New()
	userlib.DatastoreSet(invitationUUID, marshalizedInvitation)

	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	/*
		error cases:
		1. The caller already has a file with the given filename in their personal file namespace.
		2. The caller is unable to verify that the secure file share invitation pointed to by the given invitationPtr was created by senderUsername.
		3. The invitation is no longer valid due to revocation.
		4. The caller is unable to verify the integrity of the secure file share invitation pointed to by the given invitationPtr.
	*/

	// get UUID of would-be MLP to check if caller already has a file with this given filename in their personal namespace
	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return errors.New("error occurred while generating UUID for marshaled MLP struct")
	}

	// check if file with this filename already exists in caller's personal namespace
	_, ok := userlib.DatastoreGet(mlpUUID)
	if ok {
		return errors.New("error occurred, file with that name already exists in caller's personal namespace")
	}

	// retrieve marshaled secure invitation struct from datastore
	marshaledSecureInvitation, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("error occurred while retrieving marshaled inv struct")
	}

	// unmarshal the invitation struct
	var invStruct Invitation
	err = json.Unmarshal(marshaledSecureInvitation, &invStruct)
	if err != nil {
		return errors.New("error occurred while unmarshaling invitation struct")
	}

	// verify integrity/authenticity of the PKE in the invitation struct using verify key of owner
	senderVerifyKey, ok := userlib.KeystoreGet(senderUsername + "ver")
	if !ok {
		return errors.New("error occurred while retrieving sender verify key")
	}
	err = userlib.DSVerify(senderVerifyKey, invStruct.PKEFamilyPointerUUID, invStruct.SenderSignature)
	if err != nil {
		return errors.New("error occurred while verifying signature of sender")
	}

	// decrypt the pkefamilypointeruuid using your PKE secret key
	marshaledFamilyPointerUUID, err := userlib.PKEDec(userdata.PDecKey, invStruct.PKEFamilyPointerUUID)
	if err != nil {
		return errors.New("error occured while decryting the pkefamilypointeruuid")
	}

	var familyPointerUUID uuid.UUID
	err = json.Unmarshal(marshaledFamilyPointerUUID, &familyPointerUUID)
	if err != nil {
		return errors.New("error occurred while unmarshaling the family pointer UUID")
	}

	// use the family pointer UUID to get the marshaled authenticated encryption family pointer
	marshaledSecureFamPointer, ok := userlib.DatastoreGet(familyPointerUUID)
	if !ok {
		return errors.New("error occurred while retrieving the marshaled authenticated encryption of fam pointer")
	}
	////////////////// check from here
	// unmarshal the autenc
	var aeFamPointer AuthenticatedEncryption
	err = json.Unmarshal(marshaledSecureFamPointer, &aeFamPointer)
	if err != nil {
		return errors.New("error occurred while unmarshaling the authenticated encryption of fam pointer")
	}

	encKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "enc"))[:16]
	macKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "mac"))[:16]

	newMAC, err := userlib.HMACEval(macKey, aeFamPointer.Ciphertext)
	if err != nil {
		return errors.New("error occured while getting new MAC of ciphertext")
	}

	// verify
	if !userlib.HMACEqual(newMAC, aeFamPointer.MACtag) {
		return errors.New("error occurred while verifying encryption of family pointer struct")
	}

	// decrypt
	marshaledFamPointer := userlib.SymDec(encKey, aeFamPointer.Ciphertext)
	// unmarshal the fam pointer
	var famPointer FamilyPointer
	err = json.Unmarshal(marshaledFamPointer, &famPointer)
	if err != nil {
		return errors.New("error occurred while unmarshaling the fam pointer")
	}

	// NOW WE HAVE THE FAMILY POINTER STRUCT !!

	// check if the file is valid
	filePointerUUID := famPointer.FileStructPointer
	marshaledAEFileStruct, ok := userlib.DatastoreGet(filePointerUUID)
	if !ok {
		return errors.New("error occured while getting the file might be revoked or tampered")
	}

	var aeFileStruct AuthenticatedEncryption
	err = json.Unmarshal(marshaledAEFileStruct, &aeFileStruct)
	if err != nil {
		return errors.New("error occured while unmarshalizing the file struct")
	}

	fileStructMACTag, err := userlib.HMACEval(famPointer.MACKey, aeFileStruct.Ciphertext)
	if err != nil {
		return errors.New("error occured while creating a tag of file struct")
	}

	if !userlib.HMACEqual(fileStructMACTag, aeFileStruct.MACtag) {
		return errors.New("error occured while verifying the tage of file struct")
	}

	// retrieve secure file struct UUID from famPointer
	// fileStructUUID := famPointer.FileStructPointer

	// create mlp with the right info
	var mlp MiddleLayerPointer
	mlp.FileStructPointer = familyPointerUUID
	mlp.Filename = filename
	mlp.HashedUsername = userlib.Hash([]byte(userdata.Username))
	mlp.IsOwner = false

	// marshal the mlp
	marshaledMLP, err := json.Marshal(mlp)
	if err != nil {
		return errors.New("error occurred while marshaling MLP")
	}

	// create AE of MLP
	var aeMLP AuthenticatedEncryption
	encMessage := "encrypting MLP of " + filename
	macMessage := "tagging MLP of " + filename
	aeMLP, err = userdata.AuthenticatedEncryption(marshaledMLP, encMessage, macMessage)
	if err != nil {
		return errors.New("error occurred while creating authenticated encryption")
	}

	// marshal the ae
	marshaledAEmlp, err := json.Marshal(aeMLP)
	if err != nil {
		return errors.New("error occurred while marshaling")
	}

	// store the marshaled AE of MLP in datastore with the right mlp
	userlib.DatastoreSet(mlpUUID, marshaledAEmlp)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	/*
		returns error if:
		filename doesn't exist
		given filename is not currently shared with recipientUsername
		revocation cannot complete due to malicious action
	*/
	// check if file exists in caller's personal namespace
	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return errors.New("error occurred while generating UUID for marshaled MLP struct")
	}

	// check if file with this filename exists in caller's personal namespace
	marshaledMLPStruct, ok := userlib.DatastoreGet(mlpUUID)
	if !ok {
		return errors.New("error occurred, filename does not exist in caller's personal namespace")
	}

	// unmarshal MLP
	var aeMLPStruct AuthenticatedEncryption
	err = json.Unmarshal(marshaledMLPStruct, &aeMLPStruct)
	if err != nil {
		return errors.New("error occured while unmarshalizing the user mlp")
	}

	// verify and decrypt mlp
	mlpEncMessage := "encrypting MLP of " + filename
	mlpMACMessage := "tagging MLP of " + filename
	mlpBytes, err := userdata.AuthenticatedDecryption(aeMLPStruct, mlpEncMessage, mlpMACMessage)
	if err != nil {
		return errors.New("error occured while decrypting aemlp")
	}
	var mlpStruct MiddleLayerPointer
	err = json.Unmarshal(mlpBytes, &mlpStruct)

	// get keys to decrypt the AE of file struct
	// get AE of keys

	keyUUIDBytes := userlib.Hash([]byte(filename))
	keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
	keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
	keyUUID, err := uuid.FromBytes(keyUUIDBytes)
	if err != nil {
		return errors.New("error occurred while generating UUID for keys")
	}

	var encryptedKeys AuthenticatedEncryption
	encryptedKeysBytes, ok := userlib.DatastoreGet(keyUUID)
	if !ok {
		return errors.New("error occured while retrieving the key struct")
	}

	err = json.Unmarshal(encryptedKeysBytes, &encryptedKeys)
	if err != nil {
		return errors.New("error occured while unmarshalizing the key struct")
	}

	keysEncMessage := "encrypting keys of " + filename
	keysMACMessage := "tagging keys of " + filename
	concatenatedKeys, err := userdata.AuthenticatedDecryption(encryptedKeys, keysEncMessage, keysMACMessage)
	if err != nil {
		return errors.New("error occurred while verifying-and-decrypting AE of keys")
	}
	fileStructEncKey := concatenatedKeys[:16]
	fileStructMACKey := concatenatedKeys[16:32]

	// get the marshaled AE of file struct
	marshaledAEFileStruct, ok := userlib.DatastoreGet(mlpStruct.FileStructPointer)

	var aeFileStruct AuthenticatedEncryption
	err = json.Unmarshal(marshaledAEFileStruct, &aeFileStruct)
	if err != nil {
		return errors.New("error occurred while unmarshaling the ae of file struct")
	}

	// verify-and-decrypt the AE of file struct
	newMAC, err := userlib.HMACEval(fileStructMACKey, aeFileStruct.Ciphertext)
	if err != nil {
		return errors.New("error occurred while getting new MAC of ae of file struct")
	}

	if !userlib.HMACEqual(newMAC, aeFileStruct.MACtag) {
		return errors.New("error occured while verifying the file struct tag")
	}

	marshaledFileStruct := userlib.SymDec(fileStructEncKey, aeFileStruct.Ciphertext)

	// unmarshal file struct
	var fileStruct File
	err = json.Unmarshal(marshaledFileStruct, &fileStruct)
	if err != nil {
		return errors.New("error occurred while unmarshaling the file struct")
	}

	// NOW WE HAVE THE FILE STRUCT !!!
	// decrypt the sharedlist

	// append to share list
	sharedListEncKey, err := userlib.HashKDF(userdata.SourceKey, []byte("encrypt key for shared list of "+filename))
	if err != nil {
		return errors.New("error occured while creating an encryption key for shared list")
	}
	sharedListEncKey = userlib.Hash(sharedListEncKey)[:16]
	sharedListMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("mac key for shared list of "+filename))
	if err != nil {
		return errors.New("error occured while creating a mac key for shared list")
	}
	sharedListMACKey = userlib.Hash(sharedListMACKey)[:16]
	sharedListMACTag, err := userlib.HMACEval(sharedListMACKey, fileStruct.SharedListCipherText)
	if err != nil {
		return errors.New("error occured while creating a mac tag for shared list")
	}
	if !userlib.HMACEqual(sharedListMACTag, fileStruct.SharedListMACTag) {
		return errors.New("error occured while verifying the MAC tag for shared list")
	}
	marshalizedSharedList := userlib.SymDec(sharedListEncKey, fileStruct.SharedListCipherText)
	var sharedList map[string]userlib.UUID
	// var sharedList []uuid.UUID *** i changed data structure
	err = json.Unmarshal(marshalizedSharedList, &sharedList)
	if err != nil {
		return errors.New("error occured while unmarshalizing marshalizedsharedlist")
	}

	// iterate through the shared list
	// var familyPointerUUID userlib.UUID // this is uuid of the family we are revoking // uncomment???
	//var revokedPersonUUID userlib.UUID //***** uncomment this
	var revokedPersonExists bool
	for key, _ := range sharedList {
		// for i := 0; i < len(sharedList); i++ { *** i changed data structure
		if key == recipientUsername {
			revokedPersonExists = true
		}
	}

	// try to retrieve the family pointer
	// see if directrecipient username = revoked person
	// if revoked person doesn't exist return error
	if !revokedPersonExists {
		// return errors.New(fmt.Sprint(sharedList))
		return errors.New("error occurred, revoked person does not exist or file was not shared with them")
	}

	// get a new file struct uuid
	newFileStructUUID := uuid.New()                  //***** uncomment this
	oldFileStructUUID := mlpStruct.FileStructPointer //***** uncomment this

	// we update all the file pointers
	lastFilePointerUUID := fileStruct.FileContentsLast
	currentFilePointerUUID := fileStruct.FileContentsFirst
	exit := false
	count := 0
	// used for iteration
	nextFilePointerNewUUID := uuid.New()
	for !exit {
		// increment nextFilePointerNewUUID
		currentFilePointerNewUUID := nextFilePointerNewUUID // we re-store our filepointer with this UUID (and we encrypt contents with it)
		// decrypt with old UUID

		//***** uncomment this
		oldFilePointerEncKey := userlib.Hash([]byte(string(oldFileStructUUID[:]) + "enc" + strconv.Itoa(count)))[:16]
		oldFilePointerMACKey := userlib.Hash([]byte(string(oldFileStructUUID[:]) + "mac" + strconv.Itoa(count)))[:16]

		// use these keys to decrypt file pointers
		marshaledAECurrentFilePointer, ok := userlib.DatastoreGet(currentFilePointerUUID)
		if !ok {
			return errors.New("error occurred while retrieving marshaled file pointer from DS" + strconv.Itoa(count))
		}

		// unmarshal AE
		var aeCurrentFilePointer AuthenticatedEncryption
		err = json.Unmarshal(marshaledAECurrentFilePointer, &aeCurrentFilePointer)
		if err != nil {
			return errors.New("error occurred while unmarshaling AE of file pointer")
		}

		// verify-and-decrypt with old keys
		newMAC, err = userlib.HMACEval(oldFilePointerMACKey, aeCurrentFilePointer.Ciphertext)
		if err != nil {
			return errors.New("error occurred while creating new MAC for file pointer")
		}

		// verify
		if !userlib.HMACEqual(newMAC, aeCurrentFilePointer.MACtag) {
			return errors.New("error occurred while verifying MAC of file pointer")
		}

		// decrypt
		marshaledCurrentFilePointer := userlib.SymDec(oldFilePointerEncKey, aeCurrentFilePointer.Ciphertext)

		// unmarshal the current file pointer
		var currentFilePointer FilePointer
		err = json.Unmarshal(marshaledCurrentFilePointer, &currentFilePointer)
		if err != nil {
			return errors.New("error occurred while unmarshaling the current file pointer")
		}

		saveOriginalNext := currentFilePointer.NextFile //// i added august 5

		// HERE, WE HAVE THE FILE POINTER

		// do something to the file pointer struct
		// prepare for next iteration by moving UUID pointer
		// currentFilePointerUUID = currentFilePointer.NextFile // uncomment??????

		// start decrypting the contents before re-encrypting
		// retrieve marshaled AE content
		marshaledAEContent, ok := userlib.DatastoreGet(currentFilePointer.Content)
		if !ok {
			return errors.New("error occurred while retrieving content from datastore")
		}

		// unmarshal ae content
		var aeContent AuthenticatedEncryption
		err = json.Unmarshal(marshaledAEContent, &aeContent)
		if err != nil {
			return errors.New("error occurred while unmarshaling the AE of content of a file pointer")
		}

		// get keys for content using old UUIDs
		oldContentEncKey := userlib.Hash([]byte(string(currentFilePointerUUID[:]) + "enc"))[:16]
		oldContentMACKey := userlib.Hash([]byte(string(currentFilePointerUUID[:]) + "mac"))[:16]

		// verify and decrypt the content AE
		newMAC, err = userlib.HMACEval(oldContentMACKey, aeContent.Ciphertext)
		if err != nil {
			return errors.New("error occurred while getting new MAC of content")
		}

		// verify
		if !userlib.HMACEqual(newMAC, aeContent.MACtag) {
			return errors.New("error occurred while verifying MAC of content")
		}

		// decrypt
		content := userlib.SymDec(oldContentEncKey, aeContent.Ciphertext)

		// HERE, WE HAVE CONTENT

		// re-encrypt with the new filepointerUUID, create the new keys
		newContentEncKey := userlib.Hash([]byte(string(currentFilePointerNewUUID[:]) + "enc"))[:16]
		newContentMACKey := userlib.Hash([]byte(string(currentFilePointerNewUUID[:]) + "mac"))[:16]

		// create an AE of the contents
		var aeNewContent AuthenticatedEncryption
		aeNewContent.Ciphertext = userlib.SymEnc(newContentEncKey, userlib.RandomBytes(16), content)
		aeNewContent.MACtag, err = userlib.HMACEval(newContentMACKey, aeNewContent.Ciphertext)

		// marshal AE
		marshaledAENewContent, err := json.Marshal(aeNewContent)
		if err != nil {
			return errors.New("error occurred while marshaling the AE of contents with new keys")
		}

		// create new UUID to store this new content
		contentUUID := uuid.New()

		// !!!!!!!!!!!!!!!!!!!!!!!!!!!
		// store the re-encrypted data in datastore under UUID, and delete the old encrypted content from datastore
		userlib.DatastoreSet(contentUUID, marshaledAENewContent)
		userlib.DatastoreDelete(currentFilePointer.Content)

		// update file pointer with new location of content
		currentFilePointer.Content = contentUUID

		// next file pointer will be re-located to this UUID (only if this is not the last block)
		// update our current file pointer's nextfileUUID with this
		if currentFilePointerUUID != lastFilePointerUUID {
			nextFilePointerNewUUID = uuid.New()
			currentFilePointer.NextFile = nextFilePointerNewUUID

		} else {
			exit = true
			currentFilePointer.NextFile = uuid.Nil
			fileStruct.FileContentsLast = currentFilePointerNewUUID
		}

		// begin re-marshaling the file pointer
		marshaledCurrentFilePointer, err = json.Marshal(currentFilePointer)
		if err != nil {
			return errors.New("error occurred while marshaling the edited file pointer")
		}

		// re-encrypt the file pointer, now with the new file struct UUID
		newFilePointerEncKey := userlib.Hash([]byte(string(newFileStructUUID[:]) + "enc" + strconv.Itoa(count)))[:16]
		newFilePointerMACKey := userlib.Hash([]byte(string(newFileStructUUID[:]) + "mac" + strconv.Itoa(count)))[:16]
		// re-encrypt and mac
		aeCurrentFilePointer.Ciphertext = userlib.SymEnc(newFilePointerEncKey, userlib.RandomBytes(16), marshaledCurrentFilePointer)
		aeCurrentFilePointer.MACtag, err = userlib.HMACEval(newFilePointerMACKey, aeCurrentFilePointer.Ciphertext)
		if err != nil {
			return errors.New("error occurred while re-MAC-ing the file pointer ")
		}

		// re-marshal the AE of the file pointer
		marshaledAECurrentFilePointer, err = json.Marshal(aeCurrentFilePointer)
		if err != nil {
			return errors.New("error occurred while marshaling the AE of the current file pointer")
		}

		// for fileStruct.FileContentsFirst
		if count == 0 {
			fileStruct.FileContentsFirst = currentFilePointerNewUUID
		}

		// count += 1
		count += 1

		// store the current file pointer under previously specified new UUID, and delete the old d encryptefile pointer from datastore
		userlib.DatastoreSet(currentFilePointerNewUUID, marshaledAECurrentFilePointer)
		userlib.DatastoreDelete(currentFilePointerUUID)
		currentFilePointerUUID = saveOriginalNext
	}

	// remove the revoked user from sharedlist
	delete(sharedList, recipientUsername)
	//return errors.New(fmt.Sprint(sharedList))

	// we store the file struct in the new uuid location
	// re-generate new keys for encrypting the file
	/* /////// KEYS //////// */
	/* generate keys, encrypt, tag, and store it in Datastore */

	fileStructEncKey = userlib.RandomBytes(16)
	fileStructMACKey = userlib.RandomBytes(16)

	keyBytes := fileStructEncKey
	keyBytes = append(keyBytes, fileStructMACKey...)

	keyEncMessage := "encrypting keys of " + filename
	keyMACMessage := "tagging keys of " + filename
	encryptedKeys, err = userdata.AuthenticatedEncryption(keyBytes, keyEncMessage, keyMACMessage)
	if err != nil {
		return errors.New("error occurred while creating authenticated encryption of key concatenation")
	}

	// marshalize keys
	marshalizedEncryptedKeys, err := json.Marshal(encryptedKeys)
	if err != nil {
		return errors.New("error occurred while marshalizing the keys")
	}

	// key UUID generated earlier, we use the same as last time
	userlib.DatastoreSet(keyUUID, marshalizedEncryptedKeys)

	// remarshal the file struct
	marshaledFileStruct, err = json.Marshal(fileStruct)
	if err != nil {
		return errors.New("error occurred while re-marshaling file struct")
	}

	// re-encrypt it with the new keys
	aeFileStruct.Ciphertext = userlib.SymEnc(fileStructEncKey, userlib.RandomBytes(16), marshaledFileStruct)
	aeFileStruct.MACtag, err = userlib.HMACEval(fileStructMACKey, aeFileStruct.Ciphertext)
	if err != nil {
		return errors.New("error occurred while getting MAC of AE of file struct")
	}

	// re-marshal the AE of file struct before storing it
	marshaledAEFileStruct, err = json.Marshal(aeFileStruct)
	if err != nil {
		return errors.New("error occurred while re-marshaling the AE of file struct")
	}

	// re-store in Datatstore using new file struct uuid, delete the old version
	userlib.DatastoreSet(newFileStructUUID, marshaledAEFileStruct)
	userlib.DatastoreDelete(oldFileStructUUID)

	// UPDATE FAMILY POINTERS OF THE RIGHT DIRECT RECIPIENTS
	// re iterate through the shared list again
	var famPointer FamilyPointer
	var aeFamPointer AuthenticatedEncryption
	for name, aeFamPointerUUID := range sharedList {
		if name != recipientUsername { // case where recipient does not have access revoked
			// retrieve the marshaled AE of fam pointer for this direct child
			marshaledAEFamPointer, ok := userlib.DatastoreGet(aeFamPointerUUID)
			if !ok {
				return errors.New("error occurred while retrieving AE of fam pointer from datastore, direct child name " + name)
			}

			// unmarshal AE of fam pointer
			err = json.Unmarshal(marshaledAEFamPointer, &aeFamPointer)
			if err != nil {
				return errors.New("error occurred while unmarshaling the AE of family pointer")
			}

			// decrypt fam pointer using the right keys
			famPointerEncKey := userlib.Hash([]byte(string(aeFamPointerUUID[:]) + "enc"))[:16]
			famPointerMACKey := userlib.Hash([]byte(string(aeFamPointerUUID[:]) + "mac"))[:16]

			// verify and decrypt
			newMAC, err = userlib.HMACEval(famPointerMACKey, aeFamPointer.Ciphertext)
			if err != nil {
				return errors.New("error occurred while getting new MAC of family pointer")
			}

			// verify
			if !userlib.HMACEqual(newMAC, aeFamPointer.MACtag) {
				return errors.New("error occurred while verifying MAC of family pointer")
			}

			// decrypt
			marshaledFamPointer := userlib.SymDec(famPointerEncKey, aeFamPointer.Ciphertext)

			// unmarshal family pointer
			err = json.Unmarshal(marshaledFamPointer, &famPointer)
			if err != nil {
				return errors.New("error occurred while unmarshaling the family pointer")
			}

			// update the family pointer
			famPointer.FileStructPointer = newFileStructUUID
			famPointer.EncKey = fileStructEncKey
			famPointer.MACKey = fileStructMACKey

			// re-marshal fam pointer
			marshaledFamPointer, err = json.Marshal(famPointer)
			if err != nil {
				return errors.New("error occurred while re-marshaling the family pointer")
			}

			// re-encrypt fam pointer
			aeFamPointer.Ciphertext = userlib.SymEnc(famPointerEncKey, userlib.RandomBytes(16), marshaledFamPointer)
			aeFamPointer.MACtag, err = userlib.HMACEval(famPointerMACKey, aeFamPointer.Ciphertext)
			if err != nil {
				return errors.New("error occurred while creating MAC tag for AE of fam pointer")
			}

			// re-marshal the AE of fam pointer
			marshaledAEFamPointer, err = json.Marshal(aeFamPointer)
			if err != nil {
				return errors.New("error occurred while marshaling the AE of fam pointer")
			}

			// re-store it in DS
			userlib.DatastoreSet(aeFamPointerUUID, marshaledAEFamPointer)
		}
	}

	// UPDATING FILE OWNER MLP
	// update the owner's MLP
	mlpStruct.FileStructPointer = newFileStructUUID

	// begin re-storing it
	// re-marshal it
	marshaledMLPStruct, err = json.Marshal(mlpStruct)
	if err != nil {
		return errors.New("error occured while marshalizing the user's mlp struct")
	}

	// re-encrypt it with helper function
	aeMLPStruct, err = userdata.AuthenticatedEncryption(marshaledMLPStruct, mlpEncMessage, mlpMACMessage)
	if err != nil {
		return errors.New("error occurred while creating AE for owner MLP")
	}

	// re-marshal the AE of MLP
	marshaledAEMLPStruct, err := json.Marshal(aeMLPStruct)
	if err != nil {
		return errors.New("error occurred while re-marshaling the AE of MLP")
	}

	userlib.DatastoreSet(mlpUUID, marshaledAEMLPStruct)

	return nil
}
