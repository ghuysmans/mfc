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

exception No_device
exception Nfc_error of int * string
exception Invalid_key (* "You need to re-select the tag to operate with." *)
exception Denied

type dev
let dev : dev structure typ = structure "nfc_device"
type device = dev structure ptr
let strerror = foreign "nfc_strerror" (ptr dev @-> returning string)
let handle d x =
  if x = _ERFTRANS then
    raise Denied
  else if x = _EMFCAUTHFAIL then
    raise Invalid_key
  else if x < 0 then
    raise (Nfc_error (x, strerror d))

let initiator_init = foreign "nfc_initiator_init" (ptr dev @-> returning int)
let set_property_bool =
  foreign "nfc_device_set_property_bool" (ptr dev @->
  int @-> bool @-> returning int)
let open_initiator context =
  let f = (foreign "nfc_open" (ptr ctx @-> ptr char @-> returning (ptr dev))) in
  let d = f context (from_voidp char null) in
  if is_null d then
    raise No_device
  else (
    handle d (initiator_init d);
    handle d (set_property_bool d _EASY_FRAMING true);
    d
  )
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
  handle d (set_property_bool d _INFINITE_SELECT infinite_select);
  let t = make target in
  let a = addr t in
  let len =
    match target_uid with
    | None -> 0
    | Some uid -> assert (String.length uid = 4); 4
  in
  if select_passive_target d mifare_modulation target_uid len a < 1 then
    None
  else if Unsigned.UInt8.to_int (getf (getf t target_nti) sak) land 8 = 0 then
    None (* not a Mifare Classic *)
  else
    Some a

let initiator_transceive_bytes =
  foreign "nfc_initiator_transceive_bytes" (ptr dev @->
  ptr command @-> int @-> ptr_opt uint8_t @-> int @-> int @-> returning int)

let dump_c t ?limit s =
  let p = coerce (ptr t) (ptr char) s in
  let l =
    match limit with
    | None -> sizeof t
    | Some limit -> min limit (sizeof t)
  in
  for i = 0 to l - 1 do
    Printf.printf "%02x " (int_of_char !@(p +@ i))
  done;
  Printf.printf "\n"

let execute d blk f =
  let cmd = make command in
  let mc, n_send, b_recv, n_recv = f (getf cmd p) in
  setf cmd op mc;
  setf cmd block (Unsigned.UInt8.of_int blk);
  dump_c command ~limit:n_send (addr cmd);
  let x = initiator_transceive_bytes d (addr cmd) n_send b_recv n_recv (-1) in
  handle d x

let copy dest src len =
  for i = 0 to len - 1 do
    CArray.set dest i (Bytes.get src i |> int_of_char |> Unsigned.UInt8.of_int)
  done

let authenticate d t key secret blk =
  execute d blk (fun p ->
    setf (getf p mpa) auth_uid (getf (getf !@t target_nti) uid);
    copy (getf (getf p mpa) auth_key) secret 6;
    (match key with `A -> _MC_AUTH_A | `B -> _MC_AUTH_B), 12, None, 0
  )

let read d ?buf blk =
  let buf = CArray.make uint8_t 16 in
  execute d blk (fun _ ->
    _MC_READ, 2, Some (CArray.start buf), 16
  );
  buf

let dump b =
  for i = 0 to Bytes.length b - 1 do
    Printf.printf "%02x " (int_of_char (Bytes.get b i))
  done;
  Printf.printf "\n"

let dump_a a =
  CArray.iter (fun c -> Printf.printf "%02x " (Unsigned.UInt8.to_int c)) a;
  Printf.printf "\n"

let write d blk f =
  execute d blk (fun p ->
    f (getf p mpd);
    _MC_WRITE, 18, None, 0
  )

exception Inconsistent_value

let decode_value_block b =
  for i = 0 to 3 do
    let v = CArray.get b i in
    let v' = Unsigned.UInt8.lognot v in
    if v <> CArray.get b (i + 8) || v' <> CArray.get b (i + 4) then
      raise Inconsistent_value
    else if i < 3 then
      let a = CArray.get b (i + 12) in
      let a' = Unsigned.UInt8.lognot a in
      if a' <> CArray.get b (i + 13) then
        raise Inconsistent_value
  done;
  let v =
    !@ (coerce (ptr uint8_t) (ptr int32_t) (CArray.start b)) |>
    Signed.Int32.to_int
  in
  v, CArray.get b 12

let write_value d blk v a =
  write d blk (fun p ->
    failwith "TODO"
  )

let increment d ?(by=1) blk =
  if by <> 0 then (
    execute d blk (fun p ->
      setf p mpv (Signed.Int32.of_int (abs by));
      (if by > 0 then _MC_INCREMENT else _MC_DECREMENT), 6, None, 0
    );
    execute d blk (fun _ -> _MC_TRANSFER, 2, None, 0)
  )


let () =
  let c = init () in
  let d = open_initiator c in
  (match select d ~infinite_select:false with
  | Some t ->
    Printf.printf "%08x\n" (single_uid_of_t t);
    authenticate d t `A "\xFF\xFF\xFF\xFF\xFF\xFF" 0x3e;
    let buf = read d 0x3e in
    Printf.printf "value=%d\n" (decode_value_block buf |> fst);
    increment d 0x3e
  | None -> print_endline "nothing");
  close d;
  exit c
