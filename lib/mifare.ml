(** Helper *)
let test value mask =
  (int_of_char value) land mask <> 0


(** Shortcuts for access types *)
type a = [`A] (** key A *)
and b = [`B] (** key B *)
and n = [`N] (** never *)
and x = [`A | `B] (** both *)


(** Access conditions for sector trailers, see Table 7 *)
type ('a_read, 'a_write, 't_read, 't_write, 'b_read, 'b_write) t_access =
  | NAANAA: (n, a, a, n, a, a) t_access
  | NNANAN: (n, n, a, n, a, n) t_access
  | NBXNNB: (n, b, x, n, n, b) t_access
  | NNXNNN: (n, n, x, n, n, n) t_access
  | NAAAAA: (n, a, a, a, a, a) t_access
  | NBXBNB: (n, b, x, b, n, b) t_access
  | NNXBNN: (n, n, x, b, n, n) t_access
  | NNXNNN': (n, n, x, n, n, n) t_access

type t_access_wrapper =
  | T_Any: ('a, 'b, 'c, 'd, 'e, 'f) t_access -> t_access_wrapper

let bits_of_t_access = function
  (* return separate ints because of the format *)
  | T_Any NAANAA -> 0, 0, 0
  | T_Any NNANAN -> 0, 0, 1
  | T_Any NBXNNB -> 0, 1, 0
  | T_Any NNXNNN -> 0, 1, 1
  | T_Any NAAAAA -> 1, 0, 0
  | T_Any NBXBNB -> 1, 0, 1
  | T_Any NNXBNN -> 1, 1, 0
  | T_Any NNXNNN' -> 1, 1, 1

let string_of_t_access = function
  | T_Any NAANAA -> "NAANAA"
  | T_Any NNANAN -> "NNANAN"
  | T_Any NBXNNB -> "NBXNNB"
  | T_Any NNXNNN -> "NNXNNN"
  | T_Any NAAAAA -> "NAAAAA"
  | T_Any NBXBNB -> "NBXBNB"
  | T_Any NNXBNN -> "NNXBNN"
  | T_Any NNXNNN' -> "NNXNNN'"

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
type ('read, 'write, 'increment, 'decr_tran_rest) b_access =
  | XXXX: (x, x, x, x) b_access
  | XNNN: (x, n, n, n) b_access
  | XBNN: (x, b, n, n) b_access
  | XBBX: (x, b, b, x) b_access
  | XNNX: (x, n, n, x) b_access
  | BBNN: (b, b, n, n) b_access
  | BNNN: (b, n, n, n) b_access
  | NNNN: (n, n, n, n) b_access

type b_access_wrapper =
  | B_Any: ('a, 'b, 'c, 'd) b_access -> b_access_wrapper

let bits_of_b_access = function
  (* return separate ints because of the format *)
  | B_Any XXXX -> 0, 0, 0
  | B_Any XNNN -> 0, 0, 1
  | B_Any XBNN -> 0, 1, 0
  | B_Any XBBX -> 0, 1, 1
  | B_Any XNNX -> 1, 0, 0
  | B_Any BBNN -> 1, 0, 1
  | B_Any BNNN -> 1, 1, 0
  | B_Any NNNN -> 1, 1, 1

let string_of_b_access = function
  | B_Any XXXX -> "XXXX"
  | B_Any XNNN -> "XNNN"
  | B_Any XBNN -> "XBNN"
  | B_Any XBBX -> "XBBX"
  | B_Any XNNX -> "XNNX"
  | B_Any BBNN -> "BBNN"
  | B_Any BNNN -> "BNNN"
  | B_Any NNNN -> "NNNN"

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
  let c10, c20, c30 = bits_of_b_access (B_Any b0) in
  let c11, c21, c31 = bits_of_b_access (B_Any b1) in
  let c12, c22, c32 = bits_of_b_access (B_Any b2) in
  let c13, c23, c33 = bits_of_t_access (T_Any t) in
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

type (
  'a, 'b, 'c, 'd, (* block 0 *)
  'e, 'f, 'g, 'h, (* block 1 *)
  'i, 'j, 'k, 'l, (* block 2 *)
  'm, 'n, 'o, 'p, 'q, 'r, (* trailer *)
  'x (* key *)
) sector = {
  key: 'x;
  sector: int;
  s_lin: bool;
}

let authenticate_a sector key =
  assert (String.length key <= 6);
  {key = `A; sector; s_lin = true}

let authenticate_b sector key =
  assert (String.length key <= 6);
  {key = `B; sector; s_lin = true}

type ('a, 'b, 'c, 'd, 'x) block = {
  block: int; (* absolute number *)
  b_lin: bool;
}

let access_0 {sector; s_lin} =
  assert s_lin;
  {block = 4 * sector; b_lin = true}

let access_1 {sector; s_lin} =
  assert s_lin;
  {block = 4 * sector + 1; b_lin = true}

let access_2 {sector; s_lin} =
  assert s_lin;
  {block = 4 * sector + 2; b_lin = true}

(*
let access_t {sector; s_lin} =
  assert s_lin;
  {block = 4 * sector + 3; b_lin = true}
*)

let read {block; b_lin} =
  assert b_lin;
  "TODO"

let read_a = read
let read_b = read

let write {block; b_lin} value =
  assert b_lin;
  assert (Bytes.length value = 16);
  ()

let write_a = write
let write_b = write

let increment {block; b_lin} amount =
  assert b_lin;
  assert (amount >= 0);
  ()

let increment_a = increment
let increment_b = increment

let decrement {block; b_lin} amount =
  assert b_lin;
  assert (amount >= 0);
  ()

let decrement_a = decrement
let decrement_b = decrement
