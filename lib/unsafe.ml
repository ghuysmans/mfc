open Ctypes
open PosixTypes
open Foreign
include(Info.Make(Info_gen))

type ctx
let ctx : ctx structure typ = structure "nfc_context"
let init () =
  let p = allocate (ptr ctx) (from_voidp ctx null) in
  (foreign "nfc_init" (ptr (ptr ctx) @-> returning void)) p;
  if is_null !@p then
    failwith "nfc_init"
  else
    !@p
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
  else if set_property_bool d _EASY_FRAMING true < 0 then
    failwith @@ "nfc_device_set_property_bool(EASY_FRAMING): " ^ (strerror d)
  else
    d
let close = foreign "nfc_close" (ptr dev @-> returning void)

let single_uid_of_t t =
  let a = getf (getf !@t target_nti) uid in
  let f acc x = (acc lsl 8) lor Unsigned.UInt8.to_int x in
  CArray.sub a 0 4 |>
  CArray.fold_left f 0
let select_passive_target =
  foreign "nfc_initiator_select_passive_target" (ptr dev @->
  modulation @-> string_opt @-> int @-> ptr target @-> returning int)
let select ?target_uid ~infinite_select d =
  let mifare_modulation =
    let m = make modulation in
    setf m modulation_type _NMT_ISO14443A;
    setf m modulation_baud_rate _NBR_106;
    m
  in
  if set_property_bool d _INFINITE_SELECT infinite_select < 0 then
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
  ptr command @-> int @-> string_opt (* FIXME? *) @-> int @-> int @-> returning int)

let dump t s =
  let p = coerce (ptr t) (ptr char) s in
  for i = 0 to sizeof t - 1 do
    Printf.printf "%02x " (int_of_char !@(p +@ i))
  done;
  Printf.printf "\n"

let execute d key blk f =
  let cmd = make command in
  setf cmd op (match key with `A -> _MC_AUTH_A | `B -> _MC_AUTH_B);
  setf cmd block (Unsigned.UInt8.of_int blk);
  let n_send, b_recv, n_recv = f (getf cmd p) in
  let x = initiator_transceive_bytes d (addr cmd) n_send b_recv n_recv (-1) in
  if x = _ERFTRANS then
    `Denied
  else if x < 0 then
    failwith @@ "nfc_initiator_transceive_bytes: " ^ (strerror d)
  else
    `Done

let copy dest src len =
  for i = 0 to len - 1 do
    CArray.set dest i (Bytes.get src i |> int_of_char |> Unsigned.UInt8.of_int)
  done

let authenticate d t key secret blk =
  let f p =
    setf (getf p mpa) auth_uid (getf (getf !@t target_nti) uid);
    copy (getf (getf p mpa) auth_key) secret 6;
    12, None, 0
  in
  execute d key blk f


let () =
  let c = init () in
  let d = open_initiator c in
  (match select d ~infinite_select:false with
  | Some t ->
    Printf.printf "%08x\n" (single_uid_of_t t);
    ignore (authenticate d t `B "\xFF\xFF\xFF\xFF\xFF\xFF" 0x3e)
  | None -> print_endline "nothing");
  close d;
  exit c
