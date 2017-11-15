(** Shortcuts for access types *)
type a = [`A] (** key A *)
and b = [`B] (** key B *)
and n = [`N] (** never *)
and x = [`A | `B] (** both *)


(** Access conditions for sector trailers, see Table 7 *)
type ('a_read, 'a_write, 't_read, 't_write, 'b_read, 'b_write) t_access =
    NAANAA : (n, a, a, n, a, a) t_access
  | NNANAN : (n, n, a, n, a, n) t_access
  | NBXNNB : (n, b, x, n, n, b) t_access
  | NNXNNN : (n, n, x, n, n, n) t_access
  | NAAAAA : (n, a, a, a, a, a) t_access
  | NBXBNB : (n, b, x, b, n, b) t_access
  | NNXBNN : (n, n, x, b, n, n) t_access
  | NNXNNN' : (n, n, x, n, n, n) t_access

(** Existential wrapper *)
type t_access_wrapper =
    T_Any : ('a, 'b, 'c, 'd, 'e, 'f) t_access -> t_access_wrapper

val string_of_t_access : t_access_wrapper -> string
val t_access_of_trailer : bytes -> t_access_wrapper


(** Access conditions for data blocks, see Table 8 *)
type ('read, 'write, 'increment, 'decr_tran_rest) b_access =
    XXXX : (x, x, x, x) b_access
  | XNNN : (x, n, n, n) b_access
  | XBNN : (x, b, n, n) b_access
  | XBBX : (x, b, b, x) b_access
  | XNNX : (x, n, n, x) b_access
  | BBNN : (b, b, n, n) b_access
  | BNNN : (b, n, n, n) b_access
  | NNNN : (n, n, n, n) b_access

(** Existential wrapper *)
type b_access_wrapper =
    B_Any : ('a, 'b, 'c, 'd) b_access -> b_access_wrapper

val string_of_b_access : b_access_wrapper -> string
val make_access_bytes :
  ('a, 'b, 'c, 'd) b_access ->
  ('e, 'f, 'g, 'h) b_access ->
  ('i, 'j, 'k, 'l) b_access ->
  ('m, 'n, 'o, 'p, 'q, 'r) t_access ->
  char * char * char
val b_access_of_trailer :
  [< `B0 | `B1 | `B2 | `T ] ->
  bytes ->
  b_access_wrapper


type (
  _, _, _, _, (* block 0 *)
  _, _, _, _, (* block 1 *)
  _, _, _, _, (* block 2 *)
  _, _, _, _, _, _, (* trailer *)
  _ (* key *)
) sector

val authenticate_a:
  int ->
  string ->
  (_, _, _, _,
  _, _, _, _,
  _, _, _, _,
  _, _, _, _, _, _,
  [`A]) sector

val authenticate_b:
  int ->
  string ->
  (_, _, _, _,
  _, _, _, _,
  _, _, _, _,
  _, _, _, _, _, _,
  [`B]) sector

type ('read, 'write, 'increment, 'decr_tran_rest, 'key) block

val access_0:
  ('a, 'b, 'c, 'd,
  _, _, _, _,
  _, _, _, _,
  _, _, _, _, _, _,
  'x) sector ->
  ('a, 'b, 'c, 'd, 'x) block

val access_1:
  (_, _, _, _,
  'e, 'f, 'g, 'h,
  _, _, _, _,
  _, _, _, _, _, _,
  'x) sector ->
  ('e, 'f, 'g, 'h, 'x) block

val access_2:
  (_, _, _, _,
  _, _, _, _,
  'i, 'j, 'k, 'l,
  _, _, _, _, _, _,
  'x) sector ->
  ('i, 'j, 'k, 'l, 'x) block

(*
val access_t:
  (_, _, _, _,
  _, _, _, _,
  _, _, _, _,
  'm, 'n, 'o, 'p, 'q, 'r,
  'x) sector ->
  ('m, 'n, 'o, 'p, 'q, 'r, 'x) trailer
*)

val read_a: ([> `A], 'b, 'c, 'd, [`A]) block -> bytes
val read_b: ([> `B], 'b, 'c, 'd, [`B]) block -> bytes

val write_a: ('a, [> `A], 'c, 'd, [`A]) block -> bytes -> unit
val write_b: ('a, [> `B], 'c, 'd, [`B]) block -> bytes -> unit

val increment_a: ('a, 'b, [> `A], 'd, [`A]) block -> int -> unit
val increment_b: ('a, 'b, [> `B], 'd, [`B]) block -> int -> unit

val decrement_a: ('a, 'b, 'c, [> `A], [`A]) block -> int -> unit
val decrement_b: ('a, 'b, 'c, [> `B], [`B]) block -> int -> unit

(*
val transfer_a: dst:('a, 'b, 'c, 'x, [`A]) block -> unit
val transfer_b: dst:('a, 'b, 'c, 'x, [`B]) block -> unit

val restore_a: src:('a, 'b, 'c, 'x, [`A]) block -> unit
val restore_b: src:('a, 'b, 'c, 'x, [`B]) block -> unit
*)
