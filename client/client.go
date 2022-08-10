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

	// create an user struct
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
		return nil, errors.New("An error occurred while generating public keys for the user.")
	}
	user.SigKey, user.VerKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, errors.New("An error occurred while generating signature keys for the user.")
	}

	userlib.KeystoreSet(user.Username+"pke", user.PEncKey)
	userlib.KeystoreSet(user.Username+"ver", user.VerKey)

	// generate and store private keys
	user.SourceKey = userlib.Argon2Key(user.SecurePassword, user.Salt, 16)
	encKey, err := userlib.HashKDF(user.SourceKey, []byte("encryption"))
	if err != nil {
		return nil, errors.New("An error occurred while generating an encryption key for the user.")
	}
	encKey = userlib.Hash(encKey)[:16]
	macKey, err := userlib.HashKDF(user.SourceKey, []byte("mac"))
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC key for the user.")
	}
	macKey = userlib.Hash(macKey)[:16]

	// authenticated encryption on user struct
	var authenticatedUser AuthenticatedEncryption
	marshalizedUser, err := json.Marshal(user)
	if err != nil {
		return nil, errors.New("An error occurred while marshalizing the user.")
	}
	authenticatedUser.Ciphertext = userlib.SymEnc(encKey, userlib.RandomBytes(16), marshalizedUser)
	authenticatedUser.MACtag, err = userlib.HMACEval(macKey, authenticatedUser.Ciphertext)
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC tag for the authenticated user.")
	}
	marshalizedAuthenticatedUser, err := json.Marshal(authenticatedUser)
	if err != nil {
		return nil, errors.New("An error occurred while marshalizing the authenticated user.")
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
		return nil, errors.New("An error occurred while unmarshalizing the authenticated user.")
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
		return nil, errors.New("An error occurred while generating an encryption key for the user.")
	}
	encKey = userlib.Hash(encKey)[:16]
	macKey, err := userlib.HashKDF(sourceKey, []byte("mac"))
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC key for the user.")
	}
	macKey = userlib.Hash(macKey)[:16]

	// verify and decrypt user struct
	macTag, err := userlib.HMACEval(macKey, authenticatedUser.Ciphertext)
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC tag for the user.")
	}
	if !userlib.HMACEqual(macTag, authenticatedUser.MACtag) {
		return nil, errors.New("Cannot verify the MAC tag of the user.")
	}

	marshalizedUser := userlib.SymDec(encKey, authenticatedUser.Ciphertext)

	var user User

	err = json.Unmarshal(marshalizedUser, &user)
	if err != nil {
		return nil, errors.New("An error occurred while unmarshalizing the user.")
	}

	return &user, nil
}

// Helper function for authenticated encryption using user's sourcekey. */
func (userdata *User) AuthenticatedEncryption(plaintext []byte, encMessage string, macMessage string) (ae AuthenticatedEncryption, err error) {
	// generate keys
	var encryptedObject AuthenticatedEncryption

	encKey, err := userlib.HashKDF(userdata.SourceKey, []byte(encMessage))
	if err != nil {
		return ae, errors.New("An error occured while generating an encryption key for the object.")
	}
	encKey = userlib.Hash(encKey)[:16]
	macKey, err := userlib.HashKDF(userdata.SourceKey, []byte(macMessage))
	if err != nil {
		return ae, errors.New("An error occured while generating a MAC key for the object.")
	}
	macKey = userlib.Hash(macKey)[:16]

	// authenticated encryption on object
	ciphertext := userlib.SymEnc(encKey, userlib.RandomBytes(16), plaintext)
	macTag, err := userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return ae, errors.New("An error occured while generating a MAC tag for the object.")
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
		return nil, errors.New("An error occured while generating an encryption key for the object.")
	}
	encKey = userlib.Hash(encKey)[:16]
	macKey, err := userlib.HashKDF(userdata.SourceKey, []byte(macMessage))
	if err != nil {
		return nil, errors.New("An error occured while generating a MAC key for the object.")
	}
	macKey = userlib.Hash(macKey)[:16]

	macTag, err := userlib.HMACEval(macKey, ae.Ciphertext)
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC tag for the object.")
	}
	// verify and decrypt
	if !userlib.HMACEqual(macTag, ae.MACtag) {
		return nil, errors.New("Cannot verify the MAC tag of the object.")
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
		return errors.New("An error occurred while generating a MLP UUID.")
	}

	// check if file with this filename already exists in caller's personal namespace
	marshalizedAuthenticatedMLP, ok := userlib.DatastoreGet(mlpUUID)
	if !ok {
		return errors.New("MLP doesn't exist.")
	}

	var file File
	var fileUUID userlib.UUID

	var encKey []byte
	var macKey []byte
	if ok { // case 1: file already exists
		var authenticatedOldMLP AuthenticatedEncryption

		err = json.Unmarshal(marshalizedAuthenticatedMLP, &authenticatedOldMLP)
		if err != nil {
			return errors.New("An error occurred while unmarshalizing the authenticated old MLP.")
		}

		encMessage := "encrypting MLP of " + filename
		macMessage := "tagging MLP of " + filename
		marshaledMLP, err := userdata.AuthenticatedDecryption(authenticatedOldMLP, encMessage, macMessage)
		if err != nil {
			return errors.New("An error occured while decrypting the authenticated old MLP.")
		}

		var oldMLP MiddleLayerPointer
		err = json.Unmarshal(marshaledMLP, &oldMLP)
		if err != nil {
			return errors.New("An error occurred while unmarshalizing the old MLP.")
		}

		var getFileUUID userlib.UUID
		if oldMLP.IsOwner {
			// case 1-1: owner
			getFileUUID = oldMLP.FileStructPointer

			// get keys
			keyUUIDBytes := userlib.Hash([]byte(filename))
			keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
			keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
			keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
			keyUUID, err := uuid.FromBytes(keyUUIDBytes)
			if err != nil {
				return errors.New("An error occurred while generating a key UUID.")
			}
			marshalizedAuthenticatedKeys, ok := userlib.DatastoreGet(keyUUID)
			if !ok {
				return errors.New("Key doesn't exist.")
			}

			var authenticatedKeys AuthenticatedEncryption

			err = json.Unmarshal(marshalizedAuthenticatedKeys, &authenticatedKeys)
			if err != nil {
				return errors.New("An error occured while unmarshalizing the authenticated keys.")
			}

			// verify and decrypt
			encMessage := "encrypting keys of " + filename
			macMessage := "tagging keys of " + filename

			concatenatedKeys, err := userdata.AuthenticatedDecryption(authenticatedKeys, encMessage, macMessage)
			if err != nil {
				return errors.New("An error occured while decrypting the authenticated keys.")
			}
			encKey = concatenatedKeys[:16]
			macKey = concatenatedKeys[16:32]
		} else { // case 1-2: recipient
			familyPointerUUID := oldMLP.FileStructPointer
			marshalizedAuthenticatedFamilyPointer, ok := userlib.DatastoreGet(familyPointerUUID)
			if !ok {
				return errors.New("Family pointer doesn't exist.")
			}
			var authenticatedFamilyPointer AuthenticatedEncryption
			err = json.Unmarshal(marshalizedAuthenticatedFamilyPointer, &authenticatedFamilyPointer)
			if err != nil {
				return errors.New("An error occurred while unmarshalizing the authenticated family pointer.")
			}

			familyPointerEncKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "enc"))[:16]
			familyPointerMACKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "mac"))[:16]

			// verify and decrypt
			familyPointerMACTag, err := userlib.HMACEval(familyPointerMACKey, authenticatedFamilyPointer.Ciphertext)
			if err != nil {
				return errors.New("An error occurred while generating a MAC tag for the authenticated family pointer.")
			}
			if !userlib.HMACEqual(familyPointerMACTag, authenticatedFamilyPointer.MACtag) {
				return errors.New("Cannot verify the MAC tag of the authenticated family pointer.")
			}
			marshalizedFamilyPointer := userlib.SymDec(familyPointerEncKey, authenticatedFamilyPointer.Ciphertext)

			var familyPointer FamilyPointer

			err = json.Unmarshal(marshalizedFamilyPointer, &familyPointer)
			if err != nil {
				return errors.New("An error occured while umarshalizing the aithenticated family pointer.")
			}

			encKey = familyPointer.EncKey
			macKey = familyPointer.MACKey
			getFileUUID = familyPointer.FileStructPointer
		}

		// get file struct from datastore
		marshalizedAuthenticatedFile, ok := userlib.DatastoreGet(getFileUUID)
		if !ok {
			return errors.New("File doesn't exist.")
		}

		var authenticatedFile AuthenticatedEncryption

		err = json.Unmarshal(marshalizedAuthenticatedFile, &authenticatedFile)
		if err != nil {
			return errors.New("An error occurred while unmarshalizing the authenticated file.")
		}

		// verify and decrypt
		fileMACTag, err := userlib.HMACEval(macKey, authenticatedFile.Ciphertext)
		if err != nil {
			return errors.New("An error occurred while generating a MAC tag for the authenticated file.")
		}
		if !userlib.HMACEqual(fileMACTag, authenticatedFile.MACtag) {
			return errors.New("Cannot verify the MAC tag of the authenticated file.")
		}
		marshalizedFile := userlib.SymDec(encKey, authenticatedFile.Ciphertext)
		err = json.Unmarshal(marshalizedFile, &file)
		if err != nil {
			return errors.New("An error occurred while unmarshalizing the authenticated file.")
		}

		fileUUID = getFileUUID
	} else { // case 2: file doesn't exist
		file.FileOwnerName = userdata.Username

		var sharedList map[string]uuid.UUID

		sharedList = make(map[string]uuid.UUID)

		marshalizedSharedList, err := json.Marshal(sharedList)
		if err != nil {
			return errors.New("An error occured while marshalizing the shared list.")
		}

		sharedListEncKey, err := userlib.HashKDF(userdata.SourceKey, []byte("encrypt key for shared list of "+filename))
		if err != nil {
			return errors.New("An error occured while generating an encryption key for the shared list.")
		}
		sharedListEncKey = userlib.Hash(sharedListEncKey)[:16]
		sharedListMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("mac key for shared list of "+filename))
		if err != nil {
			return errors.New("An error occured while generating a MAC key for the shared list.")
		}
		sharedListMACKey = userlib.Hash(sharedListMACKey)[:16]

		file.SharedListCipherText = userlib.SymEnc(sharedListEncKey, userlib.RandomBytes(16), marshalizedSharedList)
		file.SharedListMACTag, err = userlib.HMACEval(sharedListMACKey, file.SharedListCipherText)
		if err != nil {
			return errors.New("An error occured while generating a MAC tag for the shared list.")
		}

		fileUUID = uuid.New()

		// generate keys
		encKey = userlib.RandomBytes(16)
		macKey = userlib.RandomBytes(16)

		concatenatedKeys := encKey
		concatenatedKeys = append(concatenatedKeys, macKey...)

		var authenticatedKeys AuthenticatedEncryption

		encMessage := "encrypting keys of " + filename
		macMessage := "tagging keys of " + filename
		authenticatedKeys, err = userdata.AuthenticatedEncryption(concatenatedKeys, encMessage, macMessage)
		if err != nil {
			return errors.New("An error occurred while doing authenticated encryption on the keys.")
		}

		keyUUIDBytes := userlib.Hash([]byte(filename))
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
		keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
		keyUUID, err := uuid.FromBytes(keyUUIDBytes)
		if err != nil {
			return errors.New("An error occurred while generating a key UUID.")
		}

		marshalizedEncryptedKeys, err := json.Marshal(authenticatedKeys)
		if err != nil {
			return errors.New("An error occurred while marshalizing the authenticated keys.")
		}

		userlib.DatastoreSet(keyUUID, marshalizedEncryptedKeys)

		// create middle layer pointer struct
		var mlp MiddleLayerPointer
		mlp.Filename = filename
		mlp.FileStructPointer = fileUUID
		mlp.HashedUsername = userlib.Hash([]byte(userdata.Username))
		mlp.IsOwner = true

		marshalizedMLP, err := json.Marshal(mlp)
		if err != nil {
			return errors.New("An error occurred while marshalizing the MLP.")
		}

		// encrypt and mac
		var authenticatedMLP AuthenticatedEncryption

		encMessage = "encrypting MLP of " + filename
		macMessage = "tagging MLP of " + filename
		authenticatedMLP, err = userdata.AuthenticatedEncryption(marshalizedMLP, encMessage, macMessage)
		if err != nil {
			return errors.New("An error occured while doing authenticated encryption on the marshalized MLP.")
		}

		marshalizedAuthenticatedMLP, err := json.Marshal(authenticatedMLP)
		if err != nil {
			return errors.New("An error occurred while marshalizing the authenticated MLP.")
		}

		mlpUUIDBytes = userlib.Hash([]byte(filename))
		mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
		mlpUUID, err = uuid.FromBytes(mlpUUIDBytes)
		if err != nil {
			return errors.New("An error occurred while generating authenticated MLP UUID.")
		}

		userlib.DatastoreSet(mlpUUID, marshalizedAuthenticatedMLP)
	}

	file.Count = 0
	fileContentUUID := uuid.New()
	filePointerUUID := uuid.New()

	var authenticatedContent AuthenticatedEncryption

	contentEncKey := userlib.Hash([]byte(string(filePointerUUID[:]) + "enc"))[:16]
	contentMACKey := userlib.Hash([]byte(string(filePointerUUID[:]) + "mac"))[:16]

	authenticatedContent.Ciphertext = userlib.SymEnc(contentEncKey, userlib.RandomBytes(16), content)
	authenticatedContent.MACtag, err = userlib.HMACEval(contentMACKey, authenticatedContent.Ciphertext)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag for the authenticated content.")
	}

	marshalizedAuthenticatedContent, err := json.Marshal(authenticatedContent)
	if err != nil {
		return errors.New("An error occured while marshalizing the authenticated content.")
	}
	userlib.DatastoreSet(fileContentUUID, marshalizedAuthenticatedContent)

	// create file pointer struct
	var filePointer FilePointer

	filePointer.Content = fileContentUUID
	filePointer.Index = 0

	marshalizedFilePointer, err := json.Marshal(filePointer)
	if err != nil {
		return errors.New("An error occurred while marshalizing the file pointer.")
	}

	// encrypt the file pointer with keys generated from file struct UUID and file pointer
	filePointerEncKey := userlib.Hash([]byte(string(fileUUID[:]) + "enc" + strconv.Itoa(file.Count)))[:16]
	filePointerMACKey := userlib.Hash([]byte(string(fileUUID[:]) + "mac" + strconv.Itoa(file.Count)))[:16]

	var authenticatedFilePointer AuthenticatedEncryption

	authenticatedFilePointer.Ciphertext = userlib.SymEnc(filePointerEncKey, userlib.RandomBytes(16), marshalizedFilePointer)
	authenticatedFilePointer.MACtag, err = userlib.HMACEval(filePointerMACKey, authenticatedFilePointer.Ciphertext)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag for the authenticated file pointer.")
	}

	marshalizedAuthenticatedFilePointer, err := json.Marshal(authenticatedFilePointer)
	if err != nil {
		return errors.New("An error occurred while marshalizing the authenticated file pointer.")
	}

	userlib.DatastoreSet(filePointerUUID, marshalizedAuthenticatedFilePointer)

	// save pointers in file struct
	file.FileContentsFirst = filePointerUUID
	file.FileContentsLast = filePointerUUID
	file.Count = 1

	marshalizedFile, err := json.Marshal(file)
	if err != nil {
		return errors.New("An error occurred while marshalizing the file.")
	}

	var authenticatedFile AuthenticatedEncryption

	authenticatedFile.Ciphertext = userlib.SymEnc(encKey, userlib.RandomBytes(16), marshalizedFile)
	authenticatedFile.MACtag, err = userlib.HMACEval(macKey, authenticatedFile.Ciphertext)
	if err != nil {
		return errors.New("An error occurred while generating a MAC tag for the authenticated file.")
	}
	marshalizedAuthenticatedFile, err := json.Marshal(authenticatedFile)
	if err != nil {
		return errors.New("An error occurred while marshalizing the authenticated file.")
	}

	// generate random UUID and store the file
	userlib.DatastoreSet(fileUUID, marshalizedAuthenticatedFile)

	return nil
}

/** Appends the given content to the end of the corresponding file. */
func (userdata *User) AppendToFile(filename string, content []byte) error {
	// get middle layer pointer
	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return errors.New("An error occurred while generating a MLP UUID.")
	}

	marshalizedAuthenticatedMLP, ok := userlib.DatastoreGet(mlpUUID)
	if !ok {
		return errors.New("MLP doesn't exist.")
	}

	var authenticatedMLP AuthenticatedEncryption

	err = json.Unmarshal(marshalizedAuthenticatedMLP, &authenticatedMLP)
	if err != nil {
		return errors.New("eAn rror occurred while unmarshalizing the authenticated MLP.")
	}

	encMessage := "encrypting MLP of " + filename
	macMessage := "tagging MLP of " + filename
	marshalizedMLP, err := userdata.AuthenticatedDecryption(authenticatedMLP, encMessage, macMessage)
	if err != nil {
		return errors.New("An error occurred while doing authenticated decryption on the MLP.")
	}

	var mlp MiddleLayerPointer

	err = json.Unmarshal(marshalizedMLP, &mlp)
	if err != nil {
		return errors.New("An error occurred while unmarshalizing the MLP.")
	}

	var fileUUID userlib.UUID
	var encKey []byte
	var macKey []byte
	if mlp.IsOwner { // case 1: file owner
		fileUUID = mlp.FileStructPointer

		keyUUIDBytes := userlib.Hash([]byte(filename))
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
		keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
		keyUUID, err := uuid.FromBytes(keyUUIDBytes)
		if err != nil {
			return errors.New("An error occurred while generating a key UUID.")
		}

		marshalizedAuthenticatedKeys, ok := userlib.DatastoreGet(keyUUID)
		if !ok {
			return errors.New("Key doesn't exist.")
		}

		var authenticatedKeys AuthenticatedEncryption

		err = json.Unmarshal(marshalizedAuthenticatedKeys, &authenticatedKeys)
		if err != nil {
			return errors.New("An error occurred while unmarshalizing the authenticated keys.")
		}

		encMessage := "encrypting keys of " + filename
		macMessage := "tagging keys of " + filename

		concatenatedKeys, err := userdata.AuthenticatedDecryption(authenticatedKeys, encMessage, macMessage)
		if err != nil {
			return errors.New("An error occured while doing authenticated decryption on the keys.")
		}
		encKey = concatenatedKeys[:16]
		macKey = concatenatedKeys[16:32]
	} else { // case 2: recipient
		familyPointerUUID := mlp.FileStructPointer

		marshalizedAuthenticatedFamilyPointer, ok := userlib.DatastoreGet(familyPointerUUID)
		if !ok {
			return errors.New("Family pointer doesn't exist.")
		}

		var authenticatedFamilyPointer AuthenticatedEncryption

		err = json.Unmarshal(marshalizedAuthenticatedFamilyPointer, &authenticatedFamilyPointer)
		if err != nil {
			return errors.New("An error occurred while unmarshalizing the authenticated family pointer.")
		}

		familyPointerEncKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "enc"))[:16]
		familyPointerMACKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "mac"))[:16]

		// verify and decrypt
		familyPointerMACTag, err := userlib.HMACEval(familyPointerMACKey, authenticatedFamilyPointer.Ciphertext)
		if err != nil {
			return errors.New("An error occurred while generating a MAC tag for the authenticated family pointer.")
		}
		if !userlib.HMACEqual(familyPointerMACTag, authenticatedFamilyPointer.MACtag) {
			return errors.New("Cannot verify the MAC tag of the authenticated family pointer.")
		}

		marshalizedFamilyPointer := userlib.SymDec(familyPointerEncKey, authenticatedFamilyPointer.Ciphertext)

		var familyPointer FamilyPointer

		err = json.Unmarshal(marshalizedFamilyPointer, &familyPointer)
		if err != nil {
			return errors.New("An error occured while umarshalizing the family pointer.")
		}

		fileUUID = familyPointer.FileStructPointer
		encKey = familyPointer.EncKey
		macKey = familyPointer.MACKey
	}

	marshalizedAuthenticatedFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New("File doesn't exist.")
	}

	var authenticatedFile AuthenticatedEncryption
	err = json.Unmarshal(marshalizedAuthenticatedFile, &authenticatedFile)
	if err != nil {
		return errors.New("An error occurred while unmarshalizing the authenticated file.")
	}

	// verify and decrypt
	fileMACTag, err := userlib.HMACEval(macKey, authenticatedFile.Ciphertext)
	if err != nil {
		return errors.New("An error occurred while generating a MAC tag for the authenticated file.")
	}
	if !userlib.HMACEqual(fileMACTag, authenticatedFile.MACtag) {
		return errors.New("Cannot verify the MAC tag of the file.")
	}

	marshalizedFile := userlib.SymDec(encKey, authenticatedFile.Ciphertext)

	var file File
	err = json.Unmarshal(marshalizedFile, &file)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the file.")
	}

	// encrypt and mac the appending content
	filePointerUUID := uuid.New()
	fileContentUUID := uuid.New()

	contentEncKey := userlib.Hash([]byte(string(filePointerUUID[:]) + "enc"))[:16]
	contentMACKey := userlib.Hash([]byte(string(filePointerUUID[:]) + "mac"))[:16]

	var authenticatedContent AuthenticatedEncryption
	authenticatedContent.Ciphertext = userlib.SymEnc(contentEncKey, userlib.RandomBytes(16), content)
	authenticatedContent.MACtag, err = userlib.HMACEval(contentMACKey, authenticatedContent.Ciphertext)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag for the authenticated content.")
	}

	marshalizedAuthenticatedContent, err := json.Marshal(authenticatedContent)
	if err != nil {
		return errors.New("An error occured while marshalizing the authenticated content.")
	}

	userlib.DatastoreSet(fileContentUUID, marshalizedAuthenticatedContent)

	// create file pointer
	var filePointer FilePointer

	filePointer.Content = fileContentUUID
	filePointer.Index = file.Count

	marshalizedFilePointer, err := json.Marshal(filePointer)
	if err != nil {
		return errors.New("An error occurred while marshalizing the file pointer.")
	}

	// encrypt and mac
	filePointerEncKey := userlib.Hash([]byte(string(fileUUID[:]) + "enc" + strconv.Itoa(file.Count)))[:16]
	filePointerMACKey := userlib.Hash([]byte(string(fileUUID[:]) + "mac" + strconv.Itoa(file.Count)))[:16]

	var authenticatedFilePointer AuthenticatedEncryption
	authenticatedFilePointer.Ciphertext = userlib.SymEnc(filePointerEncKey, userlib.RandomBytes(16), marshalizedFilePointer)
	authenticatedFilePointer.MACtag, err = userlib.HMACEval(filePointerMACKey, authenticatedFilePointer.Ciphertext)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag for the authenticated file pointer.")
	}

	marshalizedAuthenticatedPointer, err := json.Marshal(authenticatedFilePointer)
	if err != nil {
		return errors.New("An error occured while marshalizing the authenticated file pointer.")
	}

	userlib.DatastoreSet(filePointerUUID, marshalizedAuthenticatedPointer)

	// update the current last file pointer
	marshalizedAuthenticatedCurrentLastFilePointer, ok := userlib.DatastoreGet(file.FileContentsLast)
	if !ok {
		return errors.New("Last file pointer doesn't exist.")
	}

	var authenticatedCurrentLastFilePointer AuthenticatedEncryption

	err = json.Unmarshal(marshalizedAuthenticatedCurrentLastFilePointer, &authenticatedCurrentLastFilePointer)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the authenticated current last file pointer.")
	}

	// verify and decrypt
	currentLastPointerEncKey := userlib.Hash([]byte(string(fileUUID[:]) + "enc" + strconv.Itoa(file.Count-1)))[:16]
	currentLastPointerMACKey := userlib.Hash([]byte(string(fileUUID[:]) + "mac" + strconv.Itoa(file.Count-1)))[:16]

	currentLastPointerMACTag, err := userlib.HMACEval(currentLastPointerMACKey, authenticatedCurrentLastFilePointer.Ciphertext)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag for the authenticated current last file pointer.")
	}
	if !userlib.HMACEqual(currentLastPointerMACTag, authenticatedCurrentLastFilePointer.MACtag) {
		return errors.New("Cannot verify the MAC tag of the authenticated current last file pointer.")
	}

	marshalizedCurrentLastPointer := userlib.SymDec(currentLastPointerEncKey, authenticatedCurrentLastFilePointer.Ciphertext)

	var currentLastPointer FilePointer

	err = json.Unmarshal(marshalizedCurrentLastPointer, &currentLastPointer)
	if err != nil {
		return errors.New("An error occurred while unmarshalizing the current last file pointer.")
	}

	// update the current last file pointer
	currentLastPointer.NextFile = filePointerUUID

	marshalizedCurrentLastPointer, err = json.Marshal(currentLastPointer)
	if err != nil {
		return errors.New("An error occurred while marshalizing the current last file pointer.")
	}

	// encrypt and mac
	authenticatedCurrentLastFilePointer.Ciphertext = userlib.SymEnc(currentLastPointerEncKey, userlib.RandomBytes(16), marshalizedCurrentLastPointer)
	authenticatedCurrentLastFilePointer.MACtag, err = userlib.HMACEval(currentLastPointerMACKey, authenticatedCurrentLastFilePointer.Ciphertext)
	if err != nil {
		return errors.New("An error occurred while generating a MAC tag for the current last file pointer.")
	}

	marshalizedAuthenticatedCurrentLastFilePointer, err = json.Marshal(authenticatedCurrentLastFilePointer)
	if err != nil {
		return errors.New("An error occurred while marshalizing the authenticated current last file pointer.")
	}

	userlib.DatastoreSet(file.FileContentsLast, marshalizedAuthenticatedCurrentLastFilePointer)

	// update file
	file.Count += 1
	file.FileContentsLast = filePointerUUID

	// encrypt and mac
	marshalizedFile, err = json.Marshal(file)
	if err != nil {
		return errors.New("An error occurred while marshalizing the file.")
	}

	authenticatedFile.Ciphertext = userlib.SymEnc(encKey, userlib.RandomBytes(16), marshalizedFile)
	authenticatedFile.MACtag, err = userlib.HMACEval(macKey, authenticatedFile.Ciphertext)
	if err != nil {
		return errors.New("An error occurred while generating a MAC tag for the authenticated file.")
	}

	marshalizedAuthenticatedFile, err = json.Marshal(authenticatedFile)
	if err != nil {
		return errors.New("An error occurred while marshalizing the authenticated file.")
	}

	userlib.DatastoreSet(fileUUID, marshalizedAuthenticatedFile)

	return nil
}

/** Downloads and returns the content of the corresponding file. */
func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	// get middle layer pointer
	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return nil, errors.New("An error occurred while generating a MLP UUID.")
	}

	marshalizedAuthenticatedMLP, ok := userlib.DatastoreGet(mlpUUID)
	if !ok {
		return nil, errors.New("MLP doesn't exist.")
	}

	var authenticatedMLP AuthenticatedEncryption

	err = json.Unmarshal(marshalizedAuthenticatedMLP, &authenticatedMLP)
	if err != nil {
		return nil, errors.New("An error occurred while unmarshalizing the authenticated MLP.")
	}

	// verify and decrypt
	encMessage := "encrypting MLP of " + filename
	macMessage := "tagging MLP of " + filename
	marshalizedMLP, err := userdata.AuthenticatedDecryption(authenticatedMLP, encMessage, macMessage)
	if err != nil {
		return nil, errors.New("An error occurred while doing authenticated decryption on the MLP.")
	}

	var mlp MiddleLayerPointer

	err = json.Unmarshal(marshalizedMLP, &mlp)
	if err != nil {
		return nil, errors.New("An error occurred while unmarshalizing the MLP.")
	}

	var fileUUID userlib.UUID
	var encKey []byte
	var macKey []byte

	if mlp.IsOwner { // case 1: file owner
		fileUUID = mlp.FileStructPointer

		keyUUIDBytes := userlib.Hash([]byte(filename))
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
		keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
		keyUUID, err := uuid.FromBytes(keyUUIDBytes)
		if err != nil {
			return nil, errors.New("An error occurred while generating a key UUID.")
		}

		marshalizedAuthenticatedKeys, ok := userlib.DatastoreGet(keyUUID)
		if !ok {
			return nil, errors.New("Key doesn't exist.")
		}

		var authenticatedKeys AuthenticatedEncryption
		err = json.Unmarshal(marshalizedAuthenticatedKeys, &authenticatedKeys)
		if err != nil {
			return nil, errors.New("An error occurred while unmarshalizing the authenticated keys.")
		}

		// generate keys
		encKeyKey, err := userlib.HashKDF(userdata.SourceKey, []byte("encrypting keys of "+filename))
		if err != nil {
			return nil, errors.New("An error occurred while generating an encryption key for the keys.")
		}
		encKeyKey = userlib.Hash(encKeyKey)[:16]
		macKeyKey, err := userlib.HashKDF(userdata.SourceKey, []byte("tagging keys of "+filename))
		if err != nil {
			return nil, errors.New("An error occurred while generating a MAC key for the keys.")
		}
		macKeyKey = userlib.Hash(macKeyKey)[:16]

		// verify and decrypt
		keyMACTag, err := userlib.HMACEval(macKeyKey, authenticatedKeys.Ciphertext)
		if err != nil {
			return nil, errors.New("An error occurred while generating a MAC tag for the authenticated keys.")
		}

		if !userlib.HMACEqual(keyMACTag, authenticatedKeys.MACtag) {
			return nil, errors.New("Cannot verify the MAC tag of the keys.")
		}

		concatenatedKeys := userlib.SymDec(encKeyKey, authenticatedKeys.Ciphertext)
		encKey = concatenatedKeys[:16]
		macKey = concatenatedKeys[16:32]
	} else { // case 2: recipient
		familyPointerUUID := mlp.FileStructPointer
		marshalizedAuthenticatedFamilyPointer, ok := userlib.DatastoreGet(familyPointerUUID)
		if !ok {
			return nil, errors.New("Family pointer doesn't exist.")
		}

		var authenticatedFamilyPointer AuthenticatedEncryption
		err = json.Unmarshal(marshalizedAuthenticatedFamilyPointer, &authenticatedFamilyPointer)
		if err != nil {
			return nil, errors.New("An error occurred while unmarshalizing the authenticated family pointer.")
		}

		// derive keys
		familyPointerEncKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "enc"))[:16]
		familyPointerMACKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "mac"))[:16]

		// verify and decrypt
		familyPointerMACTag, err := userlib.HMACEval(familyPointerMACKey, authenticatedFamilyPointer.Ciphertext)
		if err != nil {
			return nil, errors.New("An error occurred while generating a MAC tag for the authenticated family pointer.")
		}
		if !userlib.HMACEqual(familyPointerMACTag, authenticatedFamilyPointer.MACtag) {
			return nil, errors.New("Cannot verify the MAC tag of the authenticated family pointer.")
		}

		marshalizedFamilyPointer := userlib.SymDec(familyPointerEncKey, authenticatedFamilyPointer.Ciphertext)

		var familyPointer FamilyPointer

		err = json.Unmarshal(marshalizedFamilyPointer, &familyPointer)
		if err != nil {
			return nil, errors.New("An error occured while umarshalizing the family pointer.")
		}

		fileUUID = familyPointer.FileStructPointer
		encKey = familyPointer.EncKey
		macKey = familyPointer.MACKey
	}
	// get file uuid from the mlp
	marshalizedAuthenticatedFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, errors.New("File doesn't exist.")
	}

	var authenticatedFile AuthenticatedEncryption
	err = json.Unmarshal(marshalizedAuthenticatedFile, &authenticatedFile)
	if err != nil {
		return nil, errors.New("An error occurred while unmarshalizing the authenticated file.")
	}

	// verify and decrypt
	fileMACTag, err := userlib.HMACEval(macKey, authenticatedFile.Ciphertext)
	if err != nil {
		return nil, errors.New("An error occurred while generating a MAC tag of the authenticated file.")
	}
	if !userlib.HMACEqual(fileMACTag, authenticatedFile.MACtag) {
		return nil, errors.New("Cannot verify the MAC tag of the authenticated file.")
	}

	marshalizedFile := userlib.SymDec(encKey, authenticatedFile.Ciphertext)

	var file File

	err = json.Unmarshal(marshalizedFile, &file)
	if err != nil {
		return nil, errors.New("An error occured while unmarshalizing the file.")
	}

	// get the file pointers from the file
	lastFilePointer := file.FileContentsLast
	currentFilePointer := file.FileContentsFirst
	count := 0
	exit := false
	for !exit {
		marshalizedAuthenticatedFilePointer, ok := userlib.DatastoreGet(currentFilePointer)
		if !ok {
			return nil, errors.New("File " + strconv.Itoa(count) + " doesn't exist.")
		}

		var authenticatedFilePointer AuthenticatedEncryption

		err = json.Unmarshal(marshalizedAuthenticatedFilePointer, &authenticatedFilePointer)
		if err != nil {
			return nil, errors.New("An error occurred while unmarshalizing the authenticated file pointer " + strconv.Itoa(count) + ".")
		}

		filePointerEncKey := userlib.Hash([]byte(string(fileUUID[:]) + "enc" + strconv.Itoa(count)))[:16]
		filePointerMACKey := userlib.Hash([]byte(string(fileUUID[:]) + "mac" + strconv.Itoa(count)))[:16]

		filePointerMACTag, err := userlib.HMACEval(filePointerMACKey, authenticatedFilePointer.Ciphertext)
		if err != nil {
			return nil, errors.New("An error occured while generating a MAC tag of the authenticated file pointer  " + strconv.Itoa(count) + ".")
		}

		// verify and decrypt
		if !userlib.HMACEqual(filePointerMACTag, authenticatedFilePointer.MACtag) {
			return nil, errors.New("Cannot verify the MAC tag of the authenticated file pointer " + strconv.Itoa(count) + ".")
		}

		marshalizedFilePointer := userlib.SymDec(filePointerEncKey, authenticatedFilePointer.Ciphertext)

		var filePointer FilePointer

		err = json.Unmarshal(marshalizedFilePointer, &filePointer)
		if err != nil {
			return nil, errors.New("An error occured while unmarshalizing the file pointer " + strconv.Itoa(count) + ".")
		}

		// get the content pointer
		marshalizedAuthenticatedContent, ok := userlib.DatastoreGet(filePointer.Content)
		if !ok {
			return nil, errors.New("File content " + strconv.Itoa(count) + " doesn't exist.")
		}

		var authenticatedContent AuthenticatedEncryption

		err = json.Unmarshal(marshalizedAuthenticatedContent, &authenticatedContent)
		if err != nil {
			return nil, errors.New("An error occurred while unmarshalizing the authenticated file content " + strconv.Itoa(count) + ".")
		}

		contentEncKey := userlib.Hash([]byte(string(currentFilePointer[:]) + "enc"))[:16]
		contentMACKey := userlib.Hash([]byte(string(currentFilePointer[:]) + "mac"))[:16]

		// verify and decrypt
		contentMACTag, err := userlib.HMACEval(contentMACKey, authenticatedContent.Ciphertext)
		if err != nil {
			return nil, errors.New("An error occurred while generating a MAC tag of the authenticated content " + strconv.Itoa(count) + ".")
		}

		if !userlib.HMACEqual(contentMACTag, authenticatedContent.MACtag) {
			return nil, errors.New("Cannot verify the MAC tag of the authenticated content " + strconv.Itoa(count) + ".")
		}

		decryptedContent := userlib.SymDec(contentEncKey, authenticatedContent.Ciphertext)

		content = append(content, decryptedContent...)

		if currentFilePointer == lastFilePointer {
			exit = true
		}

		count += 1
		currentFilePointer = filePointer.NextFile
	}

	return content, err
}

/** Creates a secure file share invitation. */
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// get middle layer pointer
	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while generating a MLP UUID")
	}

	marshalizedAuthenticatedMLP, ok := userlib.DatastoreGet(mlpUUID)
	if !ok {
		return uuid.Nil, errors.New("MLP doesn't exist.")
	}

	// verify and decrypt
	var authenticatedMLP AuthenticatedEncryption
	err = json.Unmarshal(marshalizedAuthenticatedMLP, &authenticatedMLP)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while unmarshalizing the authenticated MLP.")
	}

	encMessage := "encrypting MLP of " + filename
	macMessage := "tagging MLP of " + filename
	marshalizedMLP, err := userdata.AuthenticatedDecryption(authenticatedMLP, encMessage, macMessage)
	if err != nil {
		return uuid.Nil, errors.New("An error occurred while doing authenticated decryption on the MLP.")
	}

	var mlp MiddleLayerPointer

	err = json.Unmarshal(marshalizedMLP, &mlp)
	if err != nil {
		return uuid.Nil, errors.New("An error occured while unmarshalizing the MLP.")
	}

	var familyPointerUUID userlib.UUID

	if mlp.IsOwner { // case 1: file owner
		keyUUIDBytes := userlib.Hash([]byte(filename))
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
		keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
		keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
		keyUUID, err := uuid.FromBytes(keyUUIDBytes)
		if err != nil {
			return uuid.Nil, errors.New("An error occurred while generating a key UUID.")
		}

		var authenticatedKeys AuthenticatedEncryption

		marshalizedAuthenticatedKeys, ok := userlib.DatastoreGet(keyUUID)
		if !ok {
			return uuid.Nil, errors.New("Key doesn't exist.")
		}

		err = json.Unmarshal(marshalizedAuthenticatedKeys, &authenticatedKeys)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while unmarshalizing the authenticated keys.")
		}

		encMessage = "encrypting keys of " + filename
		macMessage = "tagging keys of " + filename
		concatenatedKeys, err := userdata.AuthenticatedDecryption(authenticatedKeys, encMessage, macMessage)
		if err != nil {
			return uuid.Nil, errors.New("An error occurred while doing authenticated encryption on the keys.")
		}

		encKey := concatenatedKeys[:16]
		macKey := concatenatedKeys[16:32]

		// get file struct uuid from mlp
		filePointerUUID := mlp.FileStructPointer

		// verify and decrypt
		marshalizedAuthenticatedFile, ok := userlib.DatastoreGet(filePointerUUID)
		if !ok {
			return uuid.Nil, errors.New("File doesn't exist.")
		}

		var authenticatedFile AuthenticatedEncryption

		err = json.Unmarshal(marshalizedAuthenticatedFile, &authenticatedFile)
		if err != nil {
			return uuid.Nil, errors.New("An error occurred while unmarshalizing the authenticated file.")
		}

		fileMACTag, err := userlib.HMACEval(macKey, authenticatedFile.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("An error occurred while generating a MAC tag for the authenticated file.")
		}

		if !userlib.HMACEqual(fileMACTag, authenticatedFile.MACtag) {
			return uuid.Nil, errors.New("Cannot verify the MAC tag of the file.")
		}

		marshalizedFile := userlib.SymDec(encKey, authenticatedFile.Ciphertext)

		var file File

		err = json.Unmarshal(marshalizedFile, &file)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while unmarshalizing the file.")
		}

		// create family pointer
		var familyPointer FamilyPointer
		familyPointer.FileStructPointer = filePointerUUID
		familyPointer.EncKey = encKey
		familyPointer.MACKey = macKey
		familyPointer.FileOwner = userdata.Username
		familyPointer.DirectRecipientName = recipientUsername

		familyPointerUUID = uuid.New()

		familyPointerEncKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "enc"))[:16]
		familyPointerMACKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "mac"))[:16]

		marshalizedFamilyPointer, err := json.Marshal(familyPointer)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while marshalizing the family pointer.")
		}

		var authenticatedFamilyPointer AuthenticatedEncryption

		// encrypt and mac
		authenticatedFamilyPointer.Ciphertext = userlib.SymEnc(familyPointerEncKey, userlib.RandomBytes(16), marshalizedFamilyPointer)
		authenticatedFamilyPointer.MACtag, err = userlib.HMACEval(familyPointerMACKey, authenticatedFamilyPointer.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while generating a MAC tag for the authenticated family pointer.")
		}

		marshalizedAuthenticatedFamilyPointer, err := json.Marshal(authenticatedFamilyPointer)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while marshalizing the authenticated family pointer.")
		}
		userlib.DatastoreSet(familyPointerUUID, marshalizedAuthenticatedFamilyPointer)

		// append to shared list
		sharedListEncKey, err := userlib.HashKDF(userdata.SourceKey, []byte("encrypt key for shared list of "+filename))
		if err != nil {
			return uuid.Nil, errors.New("An error occured while generating an encryption key for the shared list.")
		}
		sharedListEncKey = userlib.Hash(sharedListEncKey)[:16]
		sharedListMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("mac key for shared list of "+filename))
		if err != nil {
			return uuid.Nil, errors.New("An error occured while generating a mac key for the shared list.")
		}
		sharedListMACKey = userlib.Hash(sharedListMACKey)[:16]
		sharedListMACTag, err := userlib.HMACEval(sharedListMACKey, file.SharedListCipherText)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while generating a MAC tag for the shared list.")
		}
		if !userlib.HMACEqual(sharedListMACTag, file.SharedListMACTag) {
			return uuid.Nil, errors.New("Cannot verify the MAC tag of the shared list.")
		}

		marshalizedSharedList := userlib.SymDec(sharedListEncKey, file.SharedListCipherText)

		var sharedList map[string]userlib.UUID

		err = json.Unmarshal(marshalizedSharedList, &sharedList)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while unmarshalizing the shared list.")
		}

		sharedList[recipientUsername] = familyPointerUUID
		updatedMarshalizedSharedList, err := json.Marshal(sharedList)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while marshalizing the updated shared list.")
		}

		// encrypt and mac
		file.SharedListCipherText = userlib.SymEnc(sharedListEncKey, userlib.RandomBytes(16), updatedMarshalizedSharedList)
		file.SharedListMACTag, err = userlib.HMACEval(sharedListMACKey, file.SharedListCipherText)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while generating a MAC tag for the shared list.")
		}

		marshalizedFile, err = json.Marshal(file)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while marshalizing the file.")
		}

		// encrypt and mac again
		var newAuthenticatedFile AuthenticatedEncryption
		newAuthenticatedFile.Ciphertext = userlib.SymEnc(encKey, userlib.RandomBytes(16), marshalizedFile)
		newAuthenticatedFile.MACtag, err = userlib.HMACEval(macKey, newAuthenticatedFile.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while generating a MAC tag for the updated authenticated file.")
		}

		marshalizedNewAuthenticatedFile, err := json.Marshal(newAuthenticatedFile)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while marshalizing the updated authenticated file.")
		}

		userlib.DatastoreSet(filePointerUUID, marshalizedNewAuthenticatedFile)
	} else { // case 2: recipient
		familyPointerUUID = mlp.FileStructPointer

		// verify and decrypt
		marshalizedAuthenticatedFamilyPointer, ok := userlib.DatastoreGet(familyPointerUUID)
		if !ok {
			return uuid.Nil, errors.New("Family pointer doesn't exist.")
		}

		var authenticatedFamilyPointer AuthenticatedEncryption
		err = json.Unmarshal(marshalizedAuthenticatedFamilyPointer, &authenticatedFamilyPointer)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while unmarshalizing the authenticated family pointer.")
		}

		// get keys
		familyPointerEncKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "enc"))[:16]
		familyPointerMACKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "mac"))[:16]

		// verify and decrypt
		familyPointerMACTag, err := userlib.HMACEval(familyPointerMACKey, authenticatedFamilyPointer.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while generating a MAC tag for the authenticated family pointer.")
		}

		if !userlib.HMACEqual(familyPointerMACTag, authenticatedFamilyPointer.MACtag) {
			return uuid.Nil, errors.New("Cannot verify the MAC tag of the authenticated family pointer.")
		}

		marshalizedFamilyPointer := userlib.SymDec(familyPointerEncKey, authenticatedFamilyPointer.Ciphertext)

		var familyPointer FamilyPointer

		err = json.Unmarshal(marshalizedFamilyPointer, &familyPointer)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while unmarshalizing the family pointer.")
		}

		fileUUID := familyPointer.FileStructPointer
		marshalizedAuthenticatedFile, ok := userlib.DatastoreGet(fileUUID)
		if !ok {
			return uuid.Nil, errors.New("File doesn't exist.")
		}

		var authenticatedFile AuthenticatedEncryption

		err = json.Unmarshal(marshalizedAuthenticatedFile, &authenticatedFile)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while unmarshalizing the authenticated file.")
		}

		fileMACTag, err := userlib.HMACEval(familyPointer.MACKey, authenticatedFile.Ciphertext)
		if err != nil {
			return uuid.Nil, errors.New("An error occured while generating a MAC tag for the authenticated file.")
		}
		if !userlib.HMACEqual(fileMACTag, authenticatedFile.MACtag) {
			return uuid.Nil, errors.New("Cannot verify the MAC tag of the authenticated file.")
		}
	}
	// create invitation
	var invitation Invitation

	recipientPublicKey, ok := userlib.KeystoreGet(recipientUsername + "pke")
	if !ok {
		return uuid.Nil, errors.New("Recipient doesn't exist.")
	}

	marshalizedFamilyPointerUUID, err := json.Marshal(familyPointerUUID)
	if err != nil {
		return uuid.Nil, errors.New("An error occured while marshalizing the family pointer UUID.")
	}

	// encrypt with the recipient's public key
	invitation.PKEFamilyPointerUUID, err = userlib.PKEEnc(recipientPublicKey, marshalizedFamilyPointerUUID)
	if err != nil {
		return uuid.Nil, errors.New("An error occured while encrypting the family pointer with the recipient's public key.")
	}

	// sign it with the sender's private key
	invitation.SenderSignature, err = userlib.DSSign(userdata.SigKey, invitation.PKEFamilyPointerUUID)
	if err != nil {
		return uuid.Nil, errors.New("An error occured while creating a digital signature on the family pointer.")
	}

	marshalizedInvitation, err := json.Marshal(invitation)
	if err != nil {
		return uuid.Nil, errors.New("An error occured while marshalizing the invitation.")
	}

	invitationUUID := uuid.New()
	userlib.DatastoreSet(invitationUUID, marshalizedInvitation)

	return invitationUUID, nil
}

/* Accepts the secure file share invitation created by senderUsername and located at invitationPtr in Datastore
by giving the corresponding file a name of filename in the caller’s personal namespace. */
func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// get middle layer pointer
	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return errors.New("An error occurred while generating a MLP UUID.")
	}

	// check if file with this filename already exists in the caller's personal namespace
	_, ok := userlib.DatastoreGet(mlpUUID)
	if ok {
		return errors.New("MLP already exists.")
	}

	marshalizedEncryptedInvitation, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Invitation doesn't exist.")
	}

	var invitation Invitation
	err = json.Unmarshal(marshalizedEncryptedInvitation, &invitation)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the invitation.")
	}

	// verify the signature with the sender's public key
	senderVerKey, ok := userlib.KeystoreGet(senderUsername + "ver")
	if !ok {
		return errors.New("Sender's public verify key doesn't exist.")
	}
	err = userlib.DSVerify(senderVerKey, invitation.PKEFamilyPointerUUID, invitation.SenderSignature)
	if err != nil {
		return errors.New("Cannot verify the sender signature of the invitation.")
	}

	// decrypt the invitation using the recipient's private key
	marshalizedFamilyPointerUUID, err := userlib.PKEDec(userdata.PDecKey, invitation.PKEFamilyPointerUUID)
	if err != nil {
		return errors.New("An error occured while decrypting the family pointer UUID.")
	}

	var familyPointerUUID uuid.UUID

	err = json.Unmarshal(marshalizedFamilyPointerUUID, &familyPointerUUID)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the family pointer UUID.")
	}

	marshalizedAuthenticatedFamilyPointer, ok := userlib.DatastoreGet(familyPointerUUID)
	if !ok {
		return errors.New("Familt pointer doesn't exist.")
	}

	// verify and decrypt
	var authenticatedFamilyPointer AuthenticatedEncryption

	err = json.Unmarshal(marshalizedAuthenticatedFamilyPointer, &authenticatedFamilyPointer)
	if err != nil {
		return errors.New("An error occrred while unmarshalizing the authenticated family pointer.")
	}

	encKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "enc"))[:16]
	macKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "mac"))[:16]

	familyPointerMACTag, err := userlib.HMACEval(macKey, authenticatedFamilyPointer.Ciphertext)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag of the authenticated family pointer.")
	}

	if !userlib.HMACEqual(familyPointerMACTag, authenticatedFamilyPointer.MACtag) {
		return errors.New("Cannot verify the MAC tag of the family pointer.")
	}

	marshalizedFamilyPointer := userlib.SymDec(encKey, authenticatedFamilyPointer.Ciphertext)

	var familyPointer FamilyPointer

	err = json.Unmarshal(marshalizedFamilyPointer, &familyPointer)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the family pointer.")
	}

	// check if the file is valid
	fileUUID := familyPointer.FileStructPointer
	marshalizedAuthenticatedFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return errors.New("File doesn't exist.")
	}

	var authenticatedFile AuthenticatedEncryption

	err = json.Unmarshal(marshalizedAuthenticatedFile, &authenticatedFile)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the authenticated file.")
	}

	fileMACTag, err := userlib.HMACEval(familyPointer.MACKey, authenticatedFile.Ciphertext)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag for the authenticated file.")
	}

	if !userlib.HMACEqual(fileMACTag, authenticatedFile.MACtag) {
		return errors.New("Cannot verify the MAC tag of the file.")
	}

	// create middle layer pointer with essential info
	var mlp MiddleLayerPointer
	mlp.FileStructPointer = familyPointerUUID
	mlp.Filename = filename
	mlp.HashedUsername = userlib.Hash([]byte(userdata.Username))
	mlp.IsOwner = false

	marshalizedMLP, err := json.Marshal(mlp)
	if err != nil {
		return errors.New("An error occured while marshalizing the MLP.")
	}

	var authenticatedMLP AuthenticatedEncryption

	encMessage := "encrypting MLP of " + filename
	macMessage := "tagging MLP of " + filename
	authenticatedMLP, err = userdata.AuthenticatedEncryption(marshalizedMLP, encMessage, macMessage)
	if err != nil {
		return errors.New("An error occured while doing authenticated encryption on the MLP.")
	}

	marshalizedAuthenticatedMLP, err := json.Marshal(authenticatedMLP)
	if err != nil {
		return errors.New("An error occured while marshalizing the authenticated MLP.")
	}

	userlib.DatastoreSet(mlpUUID, marshalizedAuthenticatedMLP)

	return nil
}

/* Revokes access to the corresponding file from recipientUsername and any other users
with whom recipientUsername has shared the file. */
func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	// get middle layer pointer
	mlpUUIDBytes := userlib.Hash([]byte(filename))
	mlpUUIDBytes = append(mlpUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	mlpUUIDBytes = userlib.Hash(mlpUUIDBytes)[:16]
	mlpUUID, err := uuid.FromBytes(mlpUUIDBytes)
	if err != nil {
		return errors.New("An error occurred while generating a MLP UUID.")
	}

	// check if file with this filename exists in the caller's personal namespace
	marshalizedAuthenticatedMLP, ok := userlib.DatastoreGet(mlpUUID)
	if !ok {
		return errors.New("MLP doesn't exist.")
	}

	var authenticatedMLP AuthenticatedEncryption
	err = json.Unmarshal(marshalizedAuthenticatedMLP, &authenticatedMLP)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the authenticated MLP.")
	}

	// verify and decrypt
	mlpEncMessage := "encrypting MLP of " + filename
	mlpMACMessage := "tagging MLP of " + filename
	marshalizedMLP, err := userdata.AuthenticatedDecryption(authenticatedMLP, mlpEncMessage, mlpMACMessage)
	if err != nil {
		return errors.New("An error occured while doing authenticated decryption on the authenticated MLP.")
	}

	var mlp MiddleLayerPointer
	err = json.Unmarshal(marshalizedMLP, &mlp)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the MLP.")
	}

	// get keys
	keyUUIDBytes := userlib.Hash([]byte(filename))
	keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte(userdata.Username))...)
	keyUUIDBytes = append(keyUUIDBytes, userlib.Hash([]byte("keys"))...)
	keyUUIDBytes = userlib.Hash(keyUUIDBytes)[:16]
	keyUUID, err := uuid.FromBytes(keyUUIDBytes)
	if err != nil {
		return errors.New("An error occured while generating a key UUID.")
	}

	var authenticatedKeys AuthenticatedEncryption

	marshalizedAuthenticatedKeys, ok := userlib.DatastoreGet(keyUUID)
	if !ok {
		return errors.New("Key doesn't exist.")
	}

	err = json.Unmarshal(marshalizedAuthenticatedKeys, &authenticatedKeys)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the authenticated keys.")
	}

	keysEncMessage := "encrypting keys of " + filename
	keysMACMessage := "tagging keys of " + filename
	concatenatedKeys, err := userdata.AuthenticatedDecryption(authenticatedKeys, keysEncMessage, keysMACMessage)
	if err != nil {
		return errors.New("An error occured while doing authenticated decryption on the keys.")
	}

	fileEncKey := concatenatedKeys[:16]
	fileMACKey := concatenatedKeys[16:32]

	// verify and decrypt
	marshalizedAuthenticatedFile, ok := userlib.DatastoreGet(mlp.FileStructPointer)
	if !ok {
		return errors.New("File doesn't exist.")
	}

	var authenticatedFile AuthenticatedEncryption
	err = json.Unmarshal(marshalizedAuthenticatedFile, &authenticatedFile)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the authenticated file.")
	}

	familyPointerMACTag, err := userlib.HMACEval(fileMACKey, authenticatedFile.Ciphertext)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag for the authenticated file.")
	}
	if !userlib.HMACEqual(familyPointerMACTag, authenticatedFile.MACtag) {
		return errors.New("Cannot verify the MAC tag of the authenticated file.")
	}

	marshalizedFile := userlib.SymDec(fileEncKey, authenticatedFile.Ciphertext)

	var file File
	err = json.Unmarshal(marshalizedFile, &file)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the file.")
	}

	// update the shared list
	sharedListEncKey, err := userlib.HashKDF(userdata.SourceKey, []byte("encrypt key for shared list of "+filename))
	if err != nil {
		return errors.New("An error occured while generating an encryption key for the shared list.")
	}
	sharedListEncKey = userlib.Hash(sharedListEncKey)[:16]
	sharedListMACKey, err := userlib.HashKDF(userdata.SourceKey, []byte("mac key for shared list of "+filename))
	if err != nil {
		return errors.New("An error occured while generating a MAC key for the shared list.")
	}
	sharedListMACKey = userlib.Hash(sharedListMACKey)[:16]
	sharedListMACTag, err := userlib.HMACEval(sharedListMACKey, file.SharedListCipherText)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag for the shared list.")
	}
	if !userlib.HMACEqual(sharedListMACTag, file.SharedListMACTag) {
		return errors.New("Cannot verify the MAC tag of the shared list.")
	}

	marshalizedSharedList := userlib.SymDec(sharedListEncKey, file.SharedListCipherText)

	var sharedList map[string]userlib.UUID

	err = json.Unmarshal(marshalizedSharedList, &sharedList)
	if err != nil {
		return errors.New("An error occured while unmarshalizing the shared list.")
	}

	// iterate through the shared list
	var revokedPersonExists bool

	for key, _ := range sharedList {
		if key == recipientUsername {
			revokedPersonExists = true
		}
	}

	// if revoked person doesn't exist return error
	if !revokedPersonExists {
		return errors.New("The person to revoke doesn't exist.")
	}

	// get a new file uuid
	newFileUUID := uuid.New()
	oldFileUUID := mlp.FileStructPointer

	// update all file pointers
	lastFilePointerUUID := file.FileContentsLast
	currentFilePointerUUID := file.FileContentsFirst
	exit := false
	count := 0
	nextFilePointerNewUUID := uuid.New()
	for !exit {
		// increment nextFilePointerNewUUID
		currentFilePointerNewUUID := nextFilePointerNewUUID // restore file pointer with this uuid

		// verify and decrypt
		oldFilePointerEncKey := userlib.Hash([]byte(string(oldFileUUID[:]) + "enc" + strconv.Itoa(count)))[:16]
		oldFilePointerMACKey := userlib.Hash([]byte(string(oldFileUUID[:]) + "mac" + strconv.Itoa(count)))[:16]

		marshalizedAuthenticatedCurrentFilePointer, ok := userlib.DatastoreGet(currentFilePointerUUID)
		if !ok {
			return errors.New("Current file pointer " + strconv.Itoa(count) + " doesn't exist.")
		}

		var authenticatedCurrentFilePointer AuthenticatedEncryption
		err = json.Unmarshal(marshalizedAuthenticatedCurrentFilePointer, &authenticatedCurrentFilePointer)
		if err != nil {
			return errors.New("An error occured while unmarshalizing the authenticated current file pointer " + strconv.Itoa(count) + ".")
		}

		// verify and decrypt the file pointer
		familyPointerMACTag, err = userlib.HMACEval(oldFilePointerMACKey, authenticatedCurrentFilePointer.Ciphertext)
		if err != nil {
			return errors.New("An error occured while generating a MAC tag for the file " + strconv.Itoa(count) + ".")
		}

		if !userlib.HMACEqual(familyPointerMACTag, authenticatedCurrentFilePointer.MACtag) {
			return errors.New("Cannot verify the MAC tag of the authenticated current file pointer " + strconv.Itoa(count) + ".")
		}

		marshalizedCurrentFilePointer := userlib.SymDec(oldFilePointerEncKey, authenticatedCurrentFilePointer.Ciphertext)

		var currentFilePointer FilePointer

		err = json.Unmarshal(marshalizedCurrentFilePointer, &currentFilePointer)
		if err != nil {
			return errors.New("An error occured while unmarshalizing the current file pointer " + strconv.Itoa(count) + ".")
		}

		originalNextFilePointerUUID := currentFilePointer.NextFile

		// verify and decrypt the content
		marshalizedAuthenticatedContent, ok := userlib.DatastoreGet(currentFilePointer.Content)
		if !ok {
			return errors.New("File content " + strconv.Itoa(count) + " doesn't exist.")
		}

		var authenticatedContent AuthenticatedEncryption
		err = json.Unmarshal(marshalizedAuthenticatedContent, &authenticatedContent)
		if err != nil {
			return errors.New("An error occured while unmarshalizing the authenticated file content " + strconv.Itoa(count) + ".")
		}

		// get keys for content using old uuid
		oldContentEncKey := userlib.Hash([]byte(string(currentFilePointerUUID[:]) + "enc"))[:16]
		oldContentMACKey := userlib.Hash([]byte(string(currentFilePointerUUID[:]) + "mac"))[:16]

		fileContentMACTag, err := userlib.HMACEval(oldContentMACKey, authenticatedContent.Ciphertext)
		if err != nil {
			return errors.New("An error occured while generating the MAC tag of the authenticated file content " + strconv.Itoa(count) + ".")
		}

		if !userlib.HMACEqual(fileContentMACTag, authenticatedContent.MACtag) {
			return errors.New("Cannot verify the MAC tag of the authenticated file content " + strconv.Itoa(count) + ".")
		}

		content := userlib.SymDec(oldContentEncKey, authenticatedContent.Ciphertext)

		// encrypt and mac again with the new filePointerUUID and create new keys
		newContentEncKey := userlib.Hash([]byte(string(currentFilePointerNewUUID[:]) + "enc"))[:16]
		newContentMACKey := userlib.Hash([]byte(string(currentFilePointerNewUUID[:]) + "mac"))[:16]

		var authenticatedUpdatedContent AuthenticatedEncryption

		authenticatedUpdatedContent.Ciphertext = userlib.SymEnc(newContentEncKey, userlib.RandomBytes(16), content)
		authenticatedUpdatedContent.MACtag, err = userlib.HMACEval(newContentMACKey, authenticatedUpdatedContent.Ciphertext)
		if err != nil {
			return errors.New("An error occured while generating a MAC tag of the authenticated updated file content " + strconv.Itoa(count) + ".")
		}

		marshalizedAuthenticatedUpdatedContent, err := json.Marshal(authenticatedUpdatedContent)
		if err != nil {
			return errors.New("An error occured while marshalizing the authenticated updated file content " + strconv.Itoa(count) + ".")
		}

		// create new uuid to store this content
		contentUUID := uuid.New()

		// store the data that is encrypted and mac'd again and delete the old content from datastore
		userlib.DatastoreSet(contentUUID, marshalizedAuthenticatedUpdatedContent)
		userlib.DatastoreDelete(currentFilePointer.Content)

		// update the file pointer with the new location of the content
		currentFilePointer.Content = contentUUID

		// the next file pointer will be located to this uuid
		// update the current file pointer's nextFileUUID with this
		if currentFilePointerUUID != lastFilePointerUUID {
			nextFilePointerNewUUID = uuid.New()
			currentFilePointer.NextFile = nextFilePointerNewUUID
		} else {
			exit = true
			currentFilePointer.NextFile = uuid.Nil
			file.FileContentsLast = currentFilePointerNewUUID
		}

		// encrypt and mac the file pointer with the new file struct uuid
		marshalizedCurrentFilePointer, err = json.Marshal(currentFilePointer)
		if err != nil {
			return errors.New("An error occured while marshalizing the new file pointer.")
		}

		newFilePointerEncKey := userlib.Hash([]byte(string(newFileUUID[:]) + "enc" + strconv.Itoa(count)))[:16]
		newFilePointerMACKey := userlib.Hash([]byte(string(newFileUUID[:]) + "mac" + strconv.Itoa(count)))[:16]

		authenticatedCurrentFilePointer.Ciphertext = userlib.SymEnc(newFilePointerEncKey, userlib.RandomBytes(16), marshalizedCurrentFilePointer)
		authenticatedCurrentFilePointer.MACtag, err = userlib.HMACEval(newFilePointerMACKey, authenticatedCurrentFilePointer.Ciphertext)
		if err != nil {
			return errors.New("An error occured while generating a MAC tag for the authenticated current file pointer.")
		}

		marshalizedAuthenticatedCurrentFilePointer, err = json.Marshal(authenticatedCurrentFilePointer)
		if err != nil {
			return errors.New("An error occured while marshalizing the authenticated current file pointer.")
		}

		if count == 0 {
			file.FileContentsFirst = currentFilePointerNewUUID
		}

		count += 1

		// store the current file pointer under previously specified new uuid and delete the old file pointer from the datastore
		userlib.DatastoreSet(currentFilePointerNewUUID, marshalizedAuthenticatedCurrentFilePointer)
		userlib.DatastoreDelete(currentFilePointerUUID)
		currentFilePointerUUID = originalNextFilePointerUUID
	}

	// remove the user to revoke from the shared ist
	delete(sharedList, recipientUsername)

	// store the file in the new uuid location
	fileEncKey = userlib.RandomBytes(16)
	fileMACKey = userlib.RandomBytes(16)

	newConcatenatedKeys := fileEncKey
	newConcatenatedKeys = append(newConcatenatedKeys, fileMACKey...)

	keyEncMessage := "encrypting keys of " + filename
	keyMACMessage := "tagging keys of " + filename
	authenticatedNewKeys, err := userdata.AuthenticatedEncryption(newConcatenatedKeys, keyEncMessage, keyMACMessage)
	if err != nil {
		return errors.New("An error occured while doing authenticated encryption on the new keys.")
	}

	marshalizedAuthenticatedNewKeys, err := json.Marshal(authenticatedNewKeys)
	if err != nil {
		return errors.New("An error occured while marshalizing the new keys.")
	}

	userlib.DatastoreSet(keyUUID, marshalizedAuthenticatedNewKeys)

	marshalizedFile, err = json.Marshal(file)
	if err != nil {
		return errors.New("An error occured while marshalizing the file.")
	}

	authenticatedFile.Ciphertext = userlib.SymEnc(fileEncKey, userlib.RandomBytes(16), marshalizedFile)
	authenticatedFile.MACtag, err = userlib.HMACEval(fileMACKey, authenticatedFile.Ciphertext)
	if err != nil {
		return errors.New("An error occured while generating a MAC tag the authenticated file.")
	}

	marshalizedAuthenticatedFile, err = json.Marshal(authenticatedFile)
	if err != nil {
		return errors.New("An error occured while marshalizing the authenticated file.")
	}

	userlib.DatastoreSet(newFileUUID, marshalizedAuthenticatedFile)
	userlib.DatastoreDelete(oldFileUUID)

	// iterate through the shared list again and update the location for the users that are not revoked
	var familyPointer FamilyPointer
	var authenticatedFamilyPointer AuthenticatedEncryption
	for name, familyPointerUUID := range sharedList {
		if name != recipientUsername { // case: recipient does not have access revoked
			marshalizedAuthenticatedFamilyPointer, ok := userlib.DatastoreGet(familyPointerUUID)
			if !ok {
				return errors.New("Family pointer " + name + " doesn't exist.")
			}

			// verify and decrypt
			err = json.Unmarshal(marshalizedAuthenticatedFamilyPointer, &authenticatedFamilyPointer)
			if err != nil {
				return errors.New("An error occured while unmarshalizing the authenticated family pointer.")
			}

			familyPointerEncKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "enc"))[:16]
			familyPointerMACKey := userlib.Hash([]byte(string(familyPointerUUID[:]) + "mac"))[:16]

			familyPointerMACTag, err = userlib.HMACEval(familyPointerMACKey, authenticatedFamilyPointer.Ciphertext)
			if err != nil {
				return errors.New("AN error occured while generating a MAC tag for the authenticated family pointer.")
			}

			if !userlib.HMACEqual(familyPointerMACTag, authenticatedFamilyPointer.MACtag) {
				return errors.New("Cannot verify the MAC tag of the authenticated family pointer.")
			}

			marshalizedFamilyPointer := userlib.SymDec(familyPointerEncKey, authenticatedFamilyPointer.Ciphertext)

			err = json.Unmarshal(marshalizedFamilyPointer, &familyPointer)
			if err != nil {
				return errors.New("An error occured while unmarshalizing the family pointer.")
			}

			// update the family pointer
			familyPointer.FileStructPointer = newFileUUID
			familyPointer.EncKey = fileEncKey
			familyPointer.MACKey = fileMACKey

			// encrypt and mac again
			marshalizedFamilyPointer, err = json.Marshal(familyPointer)
			if err != nil {
				return errors.New("AN error occured while marshalizing the family pointer.")
			}

			authenticatedFamilyPointer.Ciphertext = userlib.SymEnc(familyPointerEncKey, userlib.RandomBytes(16), marshalizedFamilyPointer)
			authenticatedFamilyPointer.MACtag, err = userlib.HMACEval(familyPointerMACKey, authenticatedFamilyPointer.Ciphertext)
			if err != nil {
				return errors.New("An error occured while generating a MAC tag for the authenticated family pointer.")
			}

			marshalizedAuthenticatedFamilyPointer, err = json.Marshal(authenticatedFamilyPointer)
			if err != nil {
				return errors.New("An error occured while marshalizing the authenticated family pointer.")
			}

			userlib.DatastoreSet(familyPointerUUID, marshalizedAuthenticatedFamilyPointer)
		}
	}

	// update the owner's mlp
	mlp.FileStructPointer = newFileUUID

	// encrypt and mac again
	marshalizedMLP, err = json.Marshal(mlp)
	if err != nil {
		return errors.New("An error occured while marshalizing the user's MLP.")
	}

	authenticatedMLP, err = userdata.AuthenticatedEncryption(marshalizedMLP, mlpEncMessage, mlpMACMessage)
	if err != nil {
		return errors.New("An error occured while doing authenticated encryption on the user's MLP.")
	}

	marshalizedAuthenticatedMLP, err = json.Marshal(authenticatedMLP)
	if err != nil {
		return errors.New("An error occured while marshalizing the authenticated user's MLP.")
	}

	userlib.DatastoreSet(mlpUUID, marshalizedAuthenticatedMLP)

	return nil
}
