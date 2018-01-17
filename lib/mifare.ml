(** Helper *)
let test value mask =
  (int_of_char value) land mask <> 0


(** Shortcuts for access types *)
type a = [`A] (** key A *)
and b = [`B] (** key B *)
and n = [`N] (** never *)
and x = [`A | `B] (** both *)


(** Access conditions for sector trailers, see Table 7 *)
type _ t_access =
    NAANAA : <a_r: n; a_w: a; t_r: a; t_w: n; b_r: a; b_w: a> t_access
  | NNANAN : <a_r: n; a_w: n; t_r: a; t_w: n; b_r: a; b_w: n> t_access
  | NBXNNB : <a_r: n; a_w: b; t_r: x; t_w: n; b_r: n; b_w: b> t_access
  | NNXNNN : <a_r: n; a_w: n; t_r: x; t_w: n; b_r: n; b_w: n> t_access
  | NAAAAA : <a_r: n; a_w: a; t_r: a; t_w: a; b_r: a; b_w: a> t_access
  | NBXBNB : <a_r: n; a_w: b; t_r: x; t_w: b; b_r: n; b_w: b> t_access
  | NNXBNN : <a_r: n; a_w: n; t_r: x; t_w: b; b_r: n; b_w: n> t_access
  | NNXNNN' : <a_r: n; a_w: n; t_r: x; t_w: n; b_r: n; b_w: n> t_access

type t_access_wrapper = T_Any: _ t_access -> t_access_wrapper

let bits_of_t_access: type a. a t_access -> int * int * int = function
  (* return separate ints because of the format *)
  | NAANAA -> 0, 0, 0
  | NNANAN -> 0, 0, 1
  | NBXNNB -> 0, 1, 0
  | NNXNNN -> 0, 1, 1
  | NAAAAA -> 1, 0, 0
  | NBXBNB -> 1, 0, 1
  | NNXBNN -> 1, 1, 0
  | NNXNNN' -> 1, 1, 1

let string_of_t_access: type a. a t_access -> string = function
  | NAANAA -> "NAANAA"
  | NNANAN -> "NNANAN"
  | NBXNNB -> "NBXNNB"
  | NNXNNN -> "NNXNNN"
  | NAAAAA -> "NAAAAA"
  | NBXBNB -> "NBXBNB"
  | NNXBNN -> "NNXBNN"
  | NNXNNN' -> "NNXNNN'"

let t_access_of_trailer trailer =
  let c1 = test (Bytes.get trailer 7) 0x80 in
  let c2 = test (Bytes.get trailer 8) 8 in
  let c3 = test (Bytes.get trailer 8) 0x80 in
  match c1, c2, c3 with
  | false, false, false -> T_Any NAANAA
  | false, false, true -> T_Any NNANAN
  | false, true, false -> T_Any NBXNNB
  | false, true, true -> T_Any NNXNNN
  | true, false, false -> T_Any NAAAAA
  | true, false, true -> T_Any NBXBNB
  | true, true, false -> T_Any NNXBNN
  | true, true, true -> T_Any NNXNNN'


(** Access conditions for data blocks, see Table 8 *)
type _ b_access =
    XXXX : <read: x; write: x; inc: x; dec_tsf_res: x> b_access
  | XNNN : <read: x; write: n; inc: n; dec_tsf_res: n> b_access
  | XBNN : <read: x; write: b; inc: n; dec_tsf_res: n> b_access
  | XBBX : <read: x; write: b; inc: b; dec_tsf_res: x> b_access
  | XNNX : <read: x; write: n; inc: n; dec_tsf_res: x> b_access
  | BBNN : <read: b; write: b; inc: n; dec_tsf_res: n> b_access
  | BNNN : <read: b; write: n; inc: n; dec_tsf_res: n> b_access
  | NNNN : <read: n; write: n; inc: n; dec_tsf_res: n> b_access

type b_access_wrapper = B_Any: _ b_access -> b_access_wrapper

let bits_of_b_access: type a. a b_access -> int * int * int = function
  (* return separate ints because of the format *)
  | XXXX -> 0, 0, 0
  | XNNN -> 0, 0, 1
  | XBNN -> 0, 1, 0
  | XBBX -> 0, 1, 1
  | XNNX -> 1, 0, 0
  | BBNN -> 1, 0, 1
  | BNNN -> 1, 1, 0
  | NNNN -> 1, 1, 1

let string_of_b_access: type a. a b_access -> string = function
  | XXXX -> "XXXX"
  | XNNN -> "XNNN"
  | XBNN -> "XBNN"
  | XBBX -> "XBBX"
  | XNNX -> "XNNX"
  | BBNN -> "BBNN"
  | BNNN -> "BNNN"
  | NNNN -> "NNNN"

let b_access_of_bits = function
  | false, false, false -> B_Any XXXX
  | false, false, true -> B_Any XNNN
  | false, true, false -> B_Any XBNN
  | false, true, true -> B_Any XBBX
  | true, false, false -> B_Any XNNX
  | true, false, true -> B_Any BBNN
  | true, true, false -> B_Any BNNN
  | true, true, true -> B_Any NNNN

(** Bit packing according to figure 10 *)
let make_access_bytes b0 b1 b2 t =
  let c10, c20, c30 = bits_of_b_access b0 in
  let c11, c21, c31 = bits_of_b_access b1 in
  let c12, c22, c32 = bits_of_b_access b2 in
  let c13, c23, c33 = bits_of_t_access t in
  let b6, b7, b8 =
    let (<&>) a b = a lsl 1 lor b in
    let not x = 1 - x in
    lnot (c23 <&> c22 <&> c21 <&> c20 <&> c13 <&> c12 <&> c11 <&> c10),
    c13 <&> c12 <&> c11 <&> c10 <&> not c33 <&> not c32 <&> not c31 <&> not c30,
    c33 <&> c32 <&> c31 <&> c30 <&> c23 <&> c22 <&> c21 <&> c20
  in
  char_of_int (b6 land 0xFF), char_of_int b7, char_of_int b8

let b_access_of_trailer block trailer =
  let block =
    match block with
    | `B0 -> 0
    | `B1 -> 1
    | `B2 -> 2
    | `T -> 3
  in
  let c1 = test (Bytes.get trailer 7) (0x10 lsl block) in
  let c2 = test (Bytes.get trailer 8) (1 lsl block) in
  let c3 = test (Bytes.get trailer 8) (0x10 lsl block) in
  b_access_of_bits (c1, c2, c3)


(* FIXME forbid nested authentications, and
 * Ensure (monadically) that the default settings are usable,
 * i.e. allow the program to work without an Access Denied error.
 * But first, move this to an Access module. *)

type 'a sector = {
  key: 'k;
  sector: int;
  s_lin: bool;
}
constraint 'a = <
  block0: _ b_access;
  block1: _ b_access;
  block2: _ b_access;
  trailer: _ t_access;
  key: 'k;
>

let authenticate_a sector key =
  assert (String.length key <= 6);
  {key = `A; sector; s_lin = true}

let authenticate_b sector key =
  assert (String.length key <= 6);
  {key = `B; sector; s_lin = true}

type 'a block = int (* absolute number *)
constraint 'a = <access: _; key: _>

let access_0 {sector; s_lin} =
  assert s_lin;
  4 * sector

let access_1 {sector; s_lin} =
  assert s_lin;
  4 * sector + 1

let access_2 {sector; s_lin} =
  assert s_lin;
  4 * sector + 2

let access_t {sector; s_lin} =
  assert s_lin;
  4 * sector + 3

let read block =
  "TODO" (* FIXME Read *)

let read_a = read
let read_b = read

let write block value =
  assert (Bytes.length value = 16);
  () (* FIXME Write *)

let write_a = write
let write_b = write

let transfer dst =
  () (* FIXME Transfer *)

let inc ~dst block amount =
  assert (amount >= 0);
  (); (* FIXME Increment *)
  transfer dst

let inc_a = inc
let inc_b = inc

let dec ~dst block amount =
  assert (amount >= 0);
  (); (* FIXME Decrement *)
  transfer dst

let dec_a = dec
let dec_b = dec

let copy ~dst src =
  (); (* FIXME Restore *)
  transfer dst

let copy_a = copy
let copy_b = copy
