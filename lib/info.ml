open Ctypes
module Make (T : Cstubs.Types.TYPE) = struct
  open T

  type nai
  let nai : nai structure typ = structure "nfc_iso14443a_info"
  let atqa = field nai "abtAtqa" (array 2 uint8_t)
  let sak = field nai "btSak" uint8_t
  let uid_len = field nai "szUidLen" size_t
  let uid = field nai "abtUid" (array 10 uint8_t)
  let ats_len = field nai "szAtsLen" size_t
  let ats = field nai "abtAts" (array 254 uint8_t)
  let () = seal nai

  type modulation
  let modulation : modulation structure typ = structure "nfc_modulation"
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
  let target : target structure typ = structure "nfc_target"
  type t = target structure ptr
  let target_nti = field target "nti" nai
  let target_nm = field target "nm" modulation
  let () = seal target
end
