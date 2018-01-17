(** Shortcuts for access types *)
type a = [`A] (** key A *)
and b = [`B] (** key B *)
and n = [`N] (** none *)
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

val string_of_t_access : _ t_access -> string

type t_access_wrapper = T_Any: _ t_access -> t_access_wrapper
val t_access_of_trailer : bytes -> t_access_wrapper


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

val string_of_b_access : _ b_access -> string
val make_access_bytes :
  _ b_access -> _ b_access -> _ b_access ->
  _ t_access ->
  char * char * char

type b_access_wrapper = B_Any: _ b_access -> b_access_wrapper
val b_access_of_trailer :
  [< `B0 | `B1 | `B2 | `T ] ->
  bytes ->
  b_access_wrapper


type 'a sector
constraint 'a = <
  block0: _ b_access;
  block1: _ b_access;
  block2: _ b_access;
  trailer: _ t_access;
  key: _;
>

val authenticate_a:
  int ->
  string ->
  <key: a; ..> sector

val authenticate_b:
  int ->
  string ->
  <key: b; ..> sector

type 'a block
constraint 'a = <access: _; key: _>

val access_0:
  <block0: 'a; key: 'b; ..> sector ->
  <access: 'a; key: 'b> block

val access_1:
  <block1: 'a; key: 'b; ..> sector ->
  <access: 'a; key: 'b> block

val access_2:
  <block2: 'a; key: 'b; ..> sector ->
  <access: 'a; key: 'b> block

val access_t:
  <trailer: 'a; key: 'b; ..> sector ->
  <access: 'a; key: 'b> block

val read_a:
  <access: <read: [> `A]; ..> b_access; key: a> block ->
  bytes
val read_b:
  <access: <read: [> `B]; ..> b_access; key: b> block ->
  bytes

val write_a:
  <access: <write: [> `A]; ..> b_access; key: a> block ->
  bytes ->
  unit
val write_b:
  <access: <write: [> `B]; ..> b_access; key: b> block ->
  bytes ->
  unit

val inc_a:
  dst:<access: <dec_tsf_res: [> `A]; ..> b_access; key: a> block ->
  <access: <inc: [> `A]; ..> b_access; key: a> block ->
  int ->
  unit
val inc_b:
  dst:<access: <dec_tsf_res: [> `B]; ..> b_access; key: b> block ->
  <access: <inc: [> `B]; ..> b_access; key: b> block ->
  int ->
  unit

val dec_a:
  dst:<access: <dec_tsf_res: [> `A]; ..> b_access; key: a> block ->
  <access: <dec_tsf_res: [> `A]; ..> b_access; key: a> block ->
  int ->
  unit
val dec_b:
  dst:<access: <dec_tsf_res: [> `B]; ..> b_access; key: b> block ->
  <access: <dec_tsf_res: [> `B]; ..> b_access; key: b> block ->
  int ->
  unit

val copy_a:
  dst:<access: <dec_tsf_res: [> `A]; ..> b_access; key: a> block ->
  <access: <dec_tsf_res: [> `A]; ..> b_access; key: a> block ->
  unit
val copy_b:
  dst:<access: <dec_tsf_res: [> `B]; ..> b_access; key: b> block ->
  <access: <dec_tsf_res: [> `B]; ..> b_access; key: b> block ->
  unit
