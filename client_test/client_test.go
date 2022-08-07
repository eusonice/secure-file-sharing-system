package client_test

import (
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables
// ================================================
const defaultPassword = "password"
const emptyPassword = ""
const passwordTwo = "password2"
const passwordThree = "password3"
const passwordFour = "password4"
const passwordFive = "password5"
const passwordSix = "password6"
const passwordSeven = "password7"
const passwordEight = "password8"
const passwordNine = "password9"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentFour = "doing authenticated encryption a million times "
const contentFive = "is not fun"

// ================================================
// Describe(...) blocks help organize tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// a few user declarations used for testing
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	var grace *client.User
	var horace *client.User
	var ira *client.User

	// declarations for multi-session testing
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	var bobLaptop *client.User
	var bobTablet *client.User

	var err error

	// bunch of filenames for testing
	emptyFile := ""
	aliceFile := "aliceFile.txt"
	aliceFoo := "Foo.txt"
	aliceBar := "Bar.txt"
	bobFile := "bobFile.txt"
	bobFoo := "Foo.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	graceFile := "graceFile.txt"
	horaceFile := "horaceFile.txt"
	iraFile := "iraFile.txt"

	BeforeEach(func() {
		// runs before each test within this Describe block
		// reset the state of datastore and keystore so that tests do not interfere with each other
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	// helper function to measure bandwidth of a particular operation
	measureBandwidth := func(probe func()) (bandwidth int) {
		before := userlib.DatastoreGetBandwidth()
		probe()
		after := userlib.DatastoreGetBandwidth()
		return after - before
	}

	// helper function to count the number of keys in keystore
	countKeys := (func() (numKeys int) {
		m := userlib.KeystoreGetMap()
		return len(m)
	})

	// helper function to swap the datastore value at the given two string uuids
	datastoreSwap := (func(first string, second string) {
		firstUUID := uuid.Must(uuid.Parse(first))
		secondUUID := uuid.Must(uuid.Parse(second))
		one, _ := userlib.DatastoreGet(firstUUID)
		two, _ := userlib.DatastoreGet(secondUUID)
		userlib.DatastoreSet(firstUUID, two)
		userlib.DatastoreSet(secondUUID, one)
	})

	// helper function to tamper the datastore value at the given string uuid
	datastoreTamper := (func(toTamper string) {
		UUID := uuid.Must(uuid.Parse(toTamper))
		info, _ := userlib.DatastoreGet(UUID)
		info = append(info, []byte(contentFive)...)
		userlib.DatastoreSet(UUID, info)
	})

	Describe("Basic Tests", func() {
		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Custom Tests: Usernames and Passwords", func() {
		Specify("Custom Test: Testing that each username is unique and case-sensitive.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("Alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("alice", passwordTwo)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user Bob.")
			bob, err = client.GetUser("alice", passwordTwo)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("", passwordThree)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user Charles.")
			charles, err = client.GetUser("", passwordThree)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user Doris.")
			doris, err = client.GetUser("doris", passwordFour)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing password length equal to zero.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", emptyPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", emptyPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceDesktop, err = client.GetUser("alice", passwordSeven)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing two users have same password.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			datastoreSwap("408b27d3-097e-ea5a-46bf-2ab6433a7234", "0416a26b-a554-3342-86b1-954918ecad7b")

			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Getting user Bob.")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing confidentiality and integrity of user information.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			datastoreTamper("408b27d3-097e-ea5a-46bf-2ab6433a7234")

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Custom Tests: User Sessions", func() {
		Specify("Custom Test: Testing changes reflected in all current user sessions immediately.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bobLaptop, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Bob.")
			bobTablet, err = client.GetUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bobLaptop.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bobTablet.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})
	})

	Describe("Custom Tests: Cryptography and Keys", func() {
		Specify("Custom Test: Testing number of keys don't depend on the number of files stored.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			a := countKeys()

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			b := countKeys()
			Expect(a).To(Equal(b))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFoo, contentTwo)
			err = aliceLaptop.StoreFile(aliceFoo, []byte(contentTwo))
			Expect(err).To(BeNil())

			c := countKeys()
			Expect(b).To(Equal(c))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceBar, contentThree)
			err = aliceLaptop.StoreFile(aliceBar, []byte(contentThree))
			Expect(err).To(BeNil())

			d := countKeys()
			Expect(c).To(Equal(d))
		})

		Specify("Custom Test: Testing number of keys don't depend on the length of any file.", func() {
			dummy1 := make([]byte, 10000)
			dummy2 := make([]byte, 10000)

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			a := countKeys()

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, dummy1)
			err = aliceLaptop.StoreFile(aliceFile, dummy1)
			Expect(err).To(BeNil())

			b := countKeys()
			Expect(a).To(Equal(b))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, dummy2)
			err = aliceLaptop.StoreFile(aliceFile, dummy2)
			Expect(err).To(BeNil())

			c := countKeys()
			Expect(b).To(Equal(c))
		})

		Specify("Custom Test: Testing number of keys don't depend on the number of users a file has been shared with.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", passwordThree)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Doris.")
			doris, err = client.InitUser("doris", passwordFour)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Eve.")
			eve, err = client.InitUser("eve", passwordFive)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			a := countKeys()

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			b := countKeys()
			Expect(a).To(Equal(b))

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			c := countKeys()
			Expect(b).To(Equal(c))

			userlib.DebugMsg("Bob creating invite for Doris for file %s, and Doris accepting invite under name %s.", bobFile, dorisFile)
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			d := countKeys()
			Expect(c).To(Equal(d))

			userlib.DebugMsg("Bob creating invite for Eve for file %s, and Eve accepting invite under name %s.", bobFile, eveFile)
			invite, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("bob", invite, eveFile)
			Expect(err).To(BeNil())

			e := countKeys()
			Expect(d).To(Equal(e))
		})
	})

	Describe("Custom Tests: No Persistent Local State", func() {
		Specify("Custom Test: Testing different sessions can revoke access and update.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", passwordThree)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Bob")
			bobTablet, err = client.GetUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bobTablet.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceTablet, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceTablet.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = aliceTablet.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob cannot load the file.")
			data, err = bobTablet.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Charles cannot load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Doris.")
			doris, err = client.InitUser("doris", passwordFour)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Eve.")
			eve, err = client.InitUser("eve", passwordFive)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Doris cannot load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)
			invite, err = aliceTablet.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Alice creating invite for Eve for file %s, and Eve accepting invite under name %s.", aliceFile, eveFile)
			invite, err = aliceLaptop.CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("alice", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve storing file %s with content: %s", eveFile, contentFour)
			err = eve.StoreFile(eveFile, []byte(contentFour))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentFour)))

			userlib.DebugMsg("Eve appending to file %s, content: %s", eveFile, contentFive)
			err = eve.AppendToFile(eveFile, []byte(contentFive))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			data, err = aliceTablet.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentFour + contentFive)))

			userlib.DebugMsg("Alice revoking Eve's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Eve cannot load the file.")
			data, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Doris can load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentFour + contentFive)))

			userlib.DebugMsg("Checking that Eve cannot load the file.")
			data, err = eve.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Custom Tests: Files", func() {
		Specify("Custom Test: Testing confidentiality and integrity of files.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			datastoreTamper("29875f0b-7305-7781-177a-3ec7095e22ef")

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing confidentiality and integrity of appending files.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending file %s with content: %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			datastoreSwap("81fc256c-5005-ae4d-359f-653f1e7e314f", "8f990710-53a2-4ef7-910a-dd7d69fcd91d")
			datastoreSwap("d1d86fc1-b8b3-4092-ba50-0a4ba15afc05", "fd2d44b6-2024-4913-9aaf-236c2c8198b6")

			userlib.DebugMsg("Checking that Alice can load the file.")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing confidentiality and integrity of file sharing invitations.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			datastoreTamper("29875f0b-7305-7781-177a-3ec7095e22ef")

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing confidentiality and integrity of accepting file invitations.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreSet(invite, []byte("tampering!"))

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing confidentiality and integrity of revoking file access.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			datastoreTamper("29875f0b-7305-7781-177a-3ec7095e22ef")

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing attacking the entire datastore.", func() {
			var datastore map[userlib.UUID][]byte

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			datastore = userlib.DatastoreGetMap()

			for key, _ := range datastore {
				datastore[key] = []byte("A")
			}

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing prevent revoked user adversary from learning anything about future writes or appends to the file.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			bobData, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob cannot load the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that what Bob read before is not equal to the updated file.")
			aliceData, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(bobData).To(Not(Equal(aliceData)))
		})

		Specify("Custom Test: Testing filename length equal to zero.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", emptyFile, contentOne)
			err = aliceLaptop.StoreFile(emptyFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			data, err := aliceLaptop.LoadFile(emptyFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Custom Test: Testing filenames can not be globally unique.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Bob")
			bobLaptop, err = client.GetUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFoo, contentOne)
			err = aliceLaptop.StoreFile(aliceFoo, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFoo, contentTwo)
			err = bobLaptop.StoreFile(bobFoo, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			aliceData, err := aliceLaptop.LoadFile(aliceFoo)
			Expect(err).To(BeNil())
			Expect(aliceData).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			bobData, err := bobLaptop.LoadFile(bobFoo)
			Expect(err).To(BeNil())
			Expect(bobData).To(Equal([]byte(contentTwo)))

			Expect(aliceData).ToNot(Equal(bobData))
		})

		Specify("Custom Test: Testing overwriting files.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			data, err := aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentTwo)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("Custom Test: Testing when the given filename does not exist in the personal file namespace of the caller.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			_, err := aliceLaptop.LoadFile(aliceFoo)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFoo, contentThree)
			err = aliceLaptop.AppendToFile(aliceFoo, []byte(contentThree))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Custom Tests: Sharing and Revocation", func() {
		Specify("Custom Test: Testing the given filename does not exist in the personal file namespace of the caller or the given recipientUsername does not exist.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			_, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
			_, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing malicious invitation cases.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", passwordThree)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Eve.")
			eve, err = client.InitUser("eve", passwordFive)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Frank.")
			frank, err = client.InitUser("frank", passwordSix)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
			invite, err := bob.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Doris for file %s, and Doris accepting invite under name %s.", aliceFile, dorisFile)
			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("charles", invite, bobFile)
			Expect(err).ToNot(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", bobFile, charlesFile)
			newInvite, err := bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).ToNot(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).ToNot(BeNil())

			err = charles.AcceptInvitation("alice", newInvite, charlesFile)
			Expect(err).ToNot(BeNil())

			err = charles.AcceptInvitation("bob", newInvite, charlesFile)
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: Testing the caller already has a file with the given filename in their personal file namespace.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing only users who are authorized to access a file.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = aliceLaptop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob cannot load the file.")
			_, err := bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing changes to the contents of the file accessible by all authorized users.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", passwordThree)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Doris.")
			doris, err = client.InitUser("doris", passwordFour)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Eve.")
			eve, err = client.InitUser("eve", passwordFive)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Frank.")
			frank, err = client.InitUser("frank", passwordSix)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Grace.")
			grace, err = client.InitUser("grace", passwordSeven)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Horace.")
			horace, err = client.InitUser("horace", passwordEight)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Ira.")
			ira, err = client.InitUser("ira", passwordNine)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentFour)
			err = alice.StoreFile(aliceFile, []byte(contentFour))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles for file %s, and Charles accepting invite under name %s.", aliceFile, charlesFile)
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Doris for file %s, and Doris accepting invite under name %s.", bobFile, dorisFile)
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Eve for file %s, and Eve accepting invite under name %s.", bobFile, eveFile)
			invite, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("bob", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles creating invite for Frank for file %s, and Frank accepting invite under name %s.", charlesFile, frankFile)
			invite, err = charles.CreateInvitation(charlesFile, "frank")
			Expect(err).To(BeNil())

			err = frank.AcceptInvitation("charles", invite, frankFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles creating invite for Grace for file %s, and Grace accepting invite under name %s.", charlesFile, graceFile)
			invite, err = charles.CreateInvitation(charlesFile, "grace")
			Expect(err).To(BeNil())

			err = grace.AcceptInvitation("charles", invite, graceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris creating invite for Horace for file %s, and Horace accepting invite under name %s.", dorisFile, horaceFile)
			invite, err = doris.CreateInvitation(dorisFile, "horace")
			Expect(err).To(BeNil())

			err = horace.AcceptInvitation("doris", invite, horaceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Horace creating invite for Ira for file %s, and Ira accepting invite under name %s.", horaceFile, iraFile)
			invite, err = horace.CreateInvitation(horaceFile, "ira")
			Expect(err).To(BeNil())

			err = ira.AcceptInvitation("horace", invite, iraFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Ira can load the file.")
			data, err := ira.LoadFile(iraFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentFour)))

			userlib.DebugMsg("Grace appending to file %s, content: %s", graceFile, contentFive)
			err = grace.AppendToFile(graceFile, []byte(contentFive))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentFour + contentFive)))

			userlib.DebugMsg("Checking that Eve can load the file.")
			data, err = eve.LoadFile(eveFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentFour + contentFive)))
		})

		Specify("Custom Test: Testing revoking file that does not exist in the caller's personal file namespace.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFoo)
			err = alice.RevokeAccess(aliceFoo, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing any other users with who the revoked user previously shared the file also lose access.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", passwordThree)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Doris.")
			doris, err = client.InitUser("doris", passwordFour)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Eve.")
			eve, err = client.InitUser("eve", passwordFive)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charles accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Doris for file %s, and Doris accepting invite under name %s.", bobFile, dorisFile)
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Eve for file %s, and Eve accepting invite under name %s.", bobFile, eveFile)
			invite, err = alice.CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())

			err = eve.AcceptInvitation("alice", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Charles lost access to the file.")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Doris lost access to the file.")
			_, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Eve can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Custom Test: Testing revoking before accepting.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob cannot load the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Testing sharing does not create copies of the file.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", passwordTwo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			aliceData, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			bobData, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())

			Expect(aliceData).To(Equal(bobData))

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can load the file.")
			aliceNewData, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			bobNewData, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())

			Expect(aliceData).To(Not(Equal(aliceNewData)))
			Expect(bobData).To(Not(Equal(aliceNewData)))
			Expect(bobData).To(Not(Equal(bobNewData)))
			Expect(aliceNewData).To(Equal(bobNewData))
		})
	})

	Describe("Custom Tests: Efficiency", func() {
		Specify("Custom Test: Testing appending new content to previously stored files is efficient.", func() {
			dummy := make([]byte, 10000)

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, dummy)
			err = alice.StoreFile(aliceFile, dummy)
			Expect(err).To(BeNil())

			firstAppend := measureBandwidth(func() {
				userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentFive)
				err = alice.AppendToFile(aliceFile, []byte(contentFive))
				Expect(err).To(BeNil())
			})

			secondAppend := measureBandwidth(func() {
				userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentFive)
				err = alice.AppendToFile(aliceFile, []byte(contentFive))
				Expect(err).To(BeNil())
			})

			Expect(firstAppend).To(Equal(secondAppend))
		})

		Specify("Custom Test: Testing appending new content multiple times is efficient.", func() {
			dummy1 := make([]byte, 10000)
			dummy2 := make([]byte, 10000)

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, dummy1)
			err = alice.StoreFile(aliceFile, dummy1)
			Expect(err).To(BeNil())

			firstAppend := measureBandwidth(func() {
				userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentFive)
				err = alice.AppendToFile(aliceFile, []byte(contentFive))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, dummy2)
			err = alice.AppendToFile(aliceFile, dummy2)
			Expect(err).To(BeNil())

			secondAppend := measureBandwidth(func() {
				userlib.DebugMsg("Alice appending to file %s, content: %s", aliceFile, contentFive)
				err = alice.AppendToFile(aliceFile, []byte(contentFive))
				Expect(err).To(BeNil())
			})

			Expect(firstAppend).To(Equal(secondAppend))
		})
	})
})
