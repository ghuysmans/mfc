include Ctypes
let lift x = x
open Ctypes_static

let rec field : type t a. t typ -> string -> a typ -> (a, t) field =
  fun s fname ftype -> match s, fname with
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
  | _, s -> failwith ("unmatched constant: "^ s)

let enum (type a) name ?typedef ?unexpected (alist : (a * int64) list) =
  match name with
  | s ->
    failwith ("unmatched enum: "^ s)
