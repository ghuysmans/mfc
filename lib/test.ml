let () =
  let sector = Mifare.authenticate_a 0 "SECRET" in
  let block = Mifare.access_1 sector in
  print_endline (Mifare.read_a block);
  let block = Mifare.access_2 sector in
  print_endline (Mifare.read_a block);
