import Foundation
@testable import ISYEETDomain

func testUsername(_ id: String) -> String {
    switch id {
    case "81d1a713-5b97-4257-bfb4-f094a2004296": "me_test"
    case "0beaac69-d53e-48d2-b5aa-dd405b7f414d": "alice"
    case "300db02d-b75a-4922-8759-f08a0efa5a40": "bob"
    case "c36e0493-49f8-4439-aa4c-2aa333bf235f": "carol"
    case "781e65af-8b81-4d42-9fef-a6bc1253f62f": "dave"
    case "9fa56b84-e436-4423-8452-b98816524ec5": "outsider"
    case "18ae18f2-64c2-4442-a0aa-fe2ef8d2d130": "other"
    case "ee9c5bcd-53b5-4939-b07a-8e021c7b6cfc": "elsewhere"
    case "5ff860bf-1190-496c-b188-ab851db691f0": "bob"
    case "75f4499b-5920-4d38-b057-e967e297590a": "a_test"
    default: "test_user"
    }
}
