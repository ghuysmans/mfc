open Ctypes
module Make (T : Cstubs.Types.TYPE) = struct
  open T
  let _EASY_FRAMING = constant "NP_EASY_FRAMING" int
  let _ERFTRANS = constant "NFC_ERFTRANS" int
  let _NMT_ISO14443A = constant "NMT_ISO14443A" int
  let _NBR_106 = constant "NBR_106" int
  let _INFINITE_SELECT = constant "NP_INFINITE_SELECT" int
  let _EMFCAUTHFAIL = constant "NFC_EMFCAUTHFAIL" int

  type nai
  let nai : nai structure typ =
    typedef (structure "nfc_iso14443a_info") "nfc_iso14443a_info"
  let atqa = field nai "abtAtqa" (array 2 uint8_t)
  let sak = field nai "btSak" uint8_t
  let uid_len = field nai "szUidLen" size_t
  let uid = field nai "abtUid" (array 10 uint8_t)
  let ats_len = field nai "szAtsLen" size_t
  let ats = field nai "abtAts" (array 254 uint8_t)
  let () = seal nai

  type modulation
  let modulation : modulation structure typ =
    typedef (structure "nfc_modulation") "nfc_modulation"
  let modulation_type = field modulation "nmt" int
  let modulation_baud_rate = field modulation "nbr" int
  let () = seal modulation

  (*
  type nti
  let nti : nti union typ = union "nfc_target_info"
  let nti_nai = field nti "nai" nai
  (* ... *)
  let () = seal nti
  *)

  type target
  let target : target structure typ =
    typedef (structure "nfc_target") "nfc_target"
  type t = target structure ptr
  let target_nti = field target "nti" nai
  let target_nm = field target "nm" modulation
  let () = seal target

  type auth
  let auth : auth structure typ = structure "mifare_param_auth"
  let key = array 10 uint8_t
  let auth_key = field auth "abtKey" key
  let auth_uid = field auth "abtAuthUid" (array 4 uint8_t)
  let () = seal auth

  type param
  let param : param union typ =
    typedef (union "mifare_param") "mifare_param"
  let mpa = field param "mpa" auth
  let mpv = field param "mpv" int32_t
  let mpd = field param "mpd" (array 16 uint8_t)
  let () = seal param

  (* FIXME enum cmd? *)
  let _MC_AUTH_A = constant "MC_AUTH_A" uint8_t
  let _MC_AUTH_B = constant "MC_AUTH_B" uint8_t
  let _MC_READ = constant "MC_READ" uint8_t
  let _MC_TRANSFER = constant "MC_TRANSFER" uint8_t
  let _MC_WRITE = constant "MC_WRITE" uint8_t
  let _MC_DECREMENT = constant "MC_DECREMENT" uint8_t
  let _MC_INCREMENT = constant "MC_INCREMENT" uint8_t
  let _MC_STORE = constant "MC_STORE" uint8_t

  type command
  let command : command structure typ =
    typedef (structure "mifare_command") "mifare_command"
  let op = field command "op" uint8_t
  let block = field command "block" uint8_t
  let p = field command "p" param
  let () = seal command
end
