open Ctypes
open PosixTypes
open Foreign
include(Info.Make(Info_gen))

type ctx
let ctx : ctx structure typ = structure "nfc_context"
let init () =
  let p = allocate (ptr ctx) (from_voidp ctx null) in
  (foreign "nfc_init" (ptr (ptr ctx) @-> returning void)) p;
  if is_null (!@ p) then
    failwith "nfc_init"
  else
    !@ p
let exit = foreign "nfc_exit" (ptr ctx @-> returning void)

type dev
let dev : dev structure typ = structure "nfc_device"
type device = dev structure ptr
let strerror = foreign "nfc_strerror" (ptr dev @-> returning string)
let initiator_init = foreign "nfc_initiator_init" (ptr dev @-> returning int)
let set_property_bool =
  foreign "nfc_device_set_property_bool" (ptr dev @->
  int @-> bool @-> returning int)
let open_initiator context =
  let f = (foreign "nfc_open" (ptr ctx @-> ptr char @-> returning (ptr dev))) in
  let d = f context (from_voidp char null) in
  if is_null d then
    failwith "nfc_open"
  else if initiator_init d < 0 then
    failwith @@ "nfc_initiator_init: " ^ (strerror d)
  (* FIXME does this work? *)
  else if set_property_bool d 11 true < 0 then
    failwith @@ "nfc_device_set_property_bool(EASY_FRAMING): " ^ (strerror d)
  else
    d
let close = foreign "nfc_close" (ptr dev @-> returning void)

let single_uid_of_t t =
  let a = getf (getf (!@ t) target_nti) uid in
  let f acc x = (acc lsl 8) lor Unsigned.UInt8.to_int x in
  CArray.sub a 0 4 |>
  CArray.fold_left f 0
let select_passive_target =
  foreign "nfc_initiator_select_passive_target" (ptr dev @->
  modulation @-> string_opt @-> int @-> ptr target @-> returning int)
let select ?target_uid ~infinite_select d =
  let mifare_modulation =
    let m = make modulation in
    setf m modulation_type 1 (* NMT_ISO14443A *);
    setf m modulation_baud_rate 1 (* NBR_106 *);
    m
  in
  if set_property_bool d 7 infinite_select < 0 then
    failwith @@ "nfc_device_set_property_bool(INFINITE_SELECT): " ^ (strerror d)
  else
    let t = make target in (* FIXME initialize it? *)
    let a = addr t in
    let len =
      match target_uid with
      | None -> 0
      | Some uid -> assert (String.length uid = 4); 4
    in
    if select_passive_target d mifare_modulation target_uid len a < 1 then
      None
    else if Unsigned.UInt8.to_int (getf (getf t target_nti) sak) land 8 = 0 then
      None (* not a Mifare Classic, FIXME raise an exception? *)
    else
      Some a

let initiator_transceive_bytes =
  foreign "nfc_initiator_transceive_bytes" (ptr dev @->
  string @-> int @-> string_opt (* FIXME? *) @-> int @-> int @-> returning int)

let authenticate d id key block =
  let mc, key =
    match key with
    | `A k -> 96, k
    | `B k -> 97, k
  in
  let buf = Bytes.create 12 in
  Bytes.set buf 0 (Char.unsafe_chr mc);
  Bytes.set buf 1 (char_of_int block);
  Bytes.blit buf 2 key 0 6;
  (* FIXME keep a t so that we can copy this array *)
  (* FIXME is masking needed? *)
  Bytes.set buf 8 (Char.unsafe_chr (id lsr 24));
  Bytes.set buf 9 (Char.unsafe_chr (id lsr 16));
  Bytes.set buf 10 (Char.unsafe_chr (id lsr 8));
  Bytes.set buf 11 (Char.unsafe_chr id);
  match initiator_transceive_bytes d buf 12 None 0 (-1) with
  | -20 (* NFC_ERFTRANS *) ->
    `Denied
  | x when x < 0 ->
    failwith @@ "nfc_initiator_init: " ^ (strerror d)
  | x ->
    `Done

(*
struct mifare_param_value {
  uint8_t  abtValue[4];
};

(* MC_READ *) 48
(* MC_TRANSFER *) 176
(* MC_WRITE *) 160
(* MC_DECREMENT *) 192
(* MC_INCREMENT *) 193
(* MC_STORE *) 194
*)


let () =
  Printf.printf "nai is %d\n" (Ctypes.sizeof nai);
  Printf.printf "target is %d\n" (Ctypes.sizeof target);
  let c = init () in
  let d = open_initiator c in
  (match select d ~infinite_select:false with
  | None -> print_endline "nothing"
  | Some t -> Printf.printf "%08x\n" (single_uid_of_t t));
  close d;
  exit c
