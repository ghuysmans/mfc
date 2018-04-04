let () =
  (* FIXME remove struct since it's typedef'd *)
  Format.print_string "#include <nfc/nfc.h>\n";
  Cstubs.Types.write_c Format.std_formatter (module Info.Make);
  Format.pp_print_flush Format.std_formatter ()
