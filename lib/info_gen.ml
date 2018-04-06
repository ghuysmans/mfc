include Ctypes
let lift x = x
open Ctypes_static

let rec field : type t a. t typ -> string -> a typ -> (a, t) field =
  fun s fname ftype -> match s, fname with
  | Struct ({ tag = "mifare_command"} as s'), "p" ->
    let f = {ftype; fname; foffset = 2} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "mifare_command"} as s'), "block" ->
    let f = {ftype; fname; foffset = 1} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "mifare_command"} as s'), "op" ->
    let f = {ftype; fname; foffset = 0} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Union ({ utag = "mifare_param"} as s'), "mpd" ->
    let f = {ftype; fname; foffset = 0} in 
    (s'.ufields <- BoxedField f :: s'.ufields; f)
  | Union ({ utag = "mifare_param"} as s'), "mpv" ->
    let f = {ftype; fname; foffset = 0} in 
    (s'.ufields <- BoxedField f :: s'.ufields; f)
  | Union ({ utag = "mifare_param"} as s'), "mpa" ->
    let f = {ftype; fname; foffset = 0} in 
    (s'.ufields <- BoxedField f :: s'.ufields; f)
  | Struct ({ tag = "mifare_param_auth"} as s'), "abtAuthUid" ->
    let f = {ftype; fname; foffset = 6} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "mifare_param_auth"} as s'), "abtKey" ->
    let f = {ftype; fname; foffset = 0} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_target"} as s'), "nm" ->
    let f = {ftype; fname; foffset = 283} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_target"} as s'), "nti" ->
    let f = {ftype; fname; foffset = 0} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_modulation"} as s'), "nbr" ->
    let f = {ftype; fname; foffset = 4} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_modulation"} as s'), "nmt" ->
    let f = {ftype; fname; foffset = 0} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_iso14443a_info"} as s'), "abtAts" ->
    let f = {ftype; fname; foffset = 29} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_iso14443a_info"} as s'), "szAtsLen" ->
    let f = {ftype; fname; foffset = 21} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_iso14443a_info"} as s'), "abtUid" ->
    let f = {ftype; fname; foffset = 11} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_iso14443a_info"} as s'), "szUidLen" ->
    let f = {ftype; fname; foffset = 3} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_iso14443a_info"} as s'), "btSak" ->
    let f = {ftype; fname; foffset = 2} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | Struct ({ tag = "nfc_iso14443a_info"} as s'), "abtAtqa" ->
    let f = {ftype; fname; foffset = 0} in 
    (s'.fields <- BoxedField f :: s'.fields; f)
  | View { ty }, _ ->
    let { ftype; foffset; fname } = field ty fname ftype in
    { ftype; foffset; fname }
  | _ -> failwith ("Unexpected field "^ fname)

let rec seal : type a. a typ -> unit = function
  | Struct ({ tag = "mifare_command"; spec = Incomplete _ } as s') ->
    s'.spec <- Complete { size = 18; align = 1 }
  | Union ({ utag = "mifare_param"; uspec = None } as s') ->
    s'.uspec <- Some { size = 16; align = 1 }
  | Struct ({ tag = "mifare_param_auth"; spec = Incomplete _ } as s') ->
    s'.spec <- Complete { size = 10; align = 1 }
  | Struct ({ tag = "nfc_target"; spec = Incomplete _ } as s') ->
    s'.spec <- Complete { size = 291; align = 1 }
  | Struct ({ tag = "nfc_modulation"; spec = Incomplete _ } as s') ->
    s'.spec <- Complete { size = 8; align = 1 }
  | Struct ({ tag = "nfc_iso14443a_info"; spec = Incomplete _ } as s') ->
    s'.spec <- Complete { size = 283; align = 1 }
  | Struct { tag; spec = Complete _ } ->
    raise (ModifyingSealedType tag)
  | Union { utag; uspec = Some _ } ->
    raise (ModifyingSealedType utag)
  | View { ty } -> seal ty
  | _ ->
    raise (Unsupported "Sealing a non-structured type")

type 'a const = 'a
let constant (type t) name (t : t typ) : t = match t, name with
  | Ctypes_static.Primitive Cstubs_internals.Uint8_t, "MC_STORE" ->
    Unsigned.UInt8.of_string "194"
  | Ctypes_static.Primitive Cstubs_internals.Uint8_t, "MC_INCREMENT" ->
    Unsigned.UInt8.of_string "193"
  | Ctypes_static.Primitive Cstubs_internals.Uint8_t, "MC_DECREMENT" ->
    Unsigned.UInt8.of_string "192"
  | Ctypes_static.Primitive Cstubs_internals.Uint8_t, "MC_WRITE" ->
    Unsigned.UInt8.of_string "160"
  | Ctypes_static.Primitive Cstubs_internals.Uint8_t, "MC_TRANSFER" ->
    Unsigned.UInt8.of_string "176"
  | Ctypes_static.Primitive Cstubs_internals.Uint8_t, "MC_READ" ->
    Unsigned.UInt8.of_string "48"
  | Ctypes_static.Primitive Cstubs_internals.Uint8_t, "MC_AUTH_B" ->
    Unsigned.UInt8.of_string "97"
  | Ctypes_static.Primitive Cstubs_internals.Uint8_t, "MC_AUTH_A" ->
    Unsigned.UInt8.of_string "96"
  | Ctypes_static.Primitive Cstubs_internals.Int, "NFC_EMFCAUTHFAIL" ->
    -30
  | Ctypes_static.Primitive Cstubs_internals.Int, "NP_INFINITE_SELECT" ->
    7
  | Ctypes_static.Primitive Cstubs_internals.Int, "NBR_106" ->
    1
  | Ctypes_static.Primitive Cstubs_internals.Int, "NMT_ISO14443A" ->
    1
  | Ctypes_static.Primitive Cstubs_internals.Int, "NFC_ERFTRANS" ->
    -20
  | Ctypes_static.Primitive Cstubs_internals.Int, "NP_EASY_FRAMING" ->
    11
  | _, s -> failwith ("unmatched constant: "^ s)

let enum (type a) name ?typedef ?unexpected (alist : (a * int64) list) =
  match name with
  | s ->
    failwith ("unmatched enum: "^ s)
