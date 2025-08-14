# phase1
go run mpccmd.go phase1 init --domain 26 --output ./meta/phase1/init.phase1
go run mpccmd.go phase1 contribute --input ./meta/phase1/init.phase1 --output ./meta/phase1/contribute_1.phase1
go run mpccmd.go phase1 verify  --input ./meta/phase1/init.phase1 --output ./meta/phase1/contribute_1.phase1
go run mpccmd.go phase1 seal --input ./meta/phase1/contribute_1.phase1 --output ./meta/phase1/groth16.crs
echo "phase1 finish"
# n3
go run mpccmd.go phase2 init inner --circuit n3 --srs ./meta/phase1/groth16.crs --output ./meta/phase2/n3_verifier_header.phase2 --ccs ./meta/n3/verifier_header.ccs
go run mpccmd.go phase2 contribute --input ./meta/phase2/n3_verifier_header.phase2  --output ./meta/phase2/n3_contribute_1.phase2
go run mpccmd.go phase2 verify --input ./meta/phase2/n3_verifier_header.phase2  --output ./meta/phase2/n3_contribute_1.phase2
go run mpccmd.go seal --srs ./meta/phase1/groth16.crs --input ./meta/phase2/n3_contribute_1.phase2 --ccs ./meta/n3/verifier_header.ccs --pk ./meta/n3/verifier_header.pk --vk ./meta/n3/verifier_header.vk
echo "n3 mpc finish"
# neox
# v1/v2 phase2
go run mpccmd.go phase2 init inner --circuit rlp --extra v1 --srs ./meta/phase1/groth16.crs --output ./meta/phase2/rlp_init.phase2 --ccs ./meta/v1/rlp_encode_hash_extra_v1_test.ccs
go run mpccmd.go phase2 contribute --input ./meta/phase2/rlp_init.phase2  --output ./meta/phase2/rlp_contribute_1.phase2
go run mpccmd.go phase2 verify --input ./meta/phase2/rlp_init.phase2  --output ./meta/phase2/rlp_contribute_1.phase2
go run mpccmd.go seal --srs ./meta/phase1/groth16.crs --input ./meta/phase2/rlp_contribute_1.phase2 --ccs ./meta/v1/rlp_encode_hash_extra_v1_test.ccs --pk ./meta/v1/rlp_encode_hash_extra_v1_test.pk --vk ./meta/v1/rlp_encode_hash_extra_v1_test.vk
echo "neox v1 rlp mpc finish"
#
go run mpccmd.go phase2 init inner --circuit g2 --extra v1 --srs ./meta/phase1/groth16.crs --output ./meta/phase2/g2_init.phase2 --ccs ./meta/v1/to_g2_hash.ccs
go run mpccmd.go phase2 contribute --input ./meta/phase2/g2_init.phase2  --output ./meta/phase2/g2_contribute_1.phase2
go run mpccmd.go phase2 verify --input ./meta/phase2/g2_init.phase2  --output ./meta/phase2/g2_contribute_1.phase2
go run mpccmd.go seal --srs ./meta/phase1/groth16.crs --input ./meta/phase2/g2_contribute_1.phase2 --ccs ./meta/v1/to_g2_hash.ccs --pk ./meta/v1/to_g2_hash.pk --vk ./meta/v1/to_g2_hash.vk
echo "neox v1 g2 mpc finish"
#
go run mpccmd.go phase2 init outer --extra v1 --srs ./meta/phase1/groth16.crs --output ./meta/phase2/outer_init.phase2 --ccs ./meta/v1/verify_header_extra_v1.ccs --ccs1 ./meta/v1/rlp_encode_hash_extra_v1_test.ccs --ccs2 ./meta/v1/to_g2_hash.ccs --vk1 ./meta/v1/rlp_encode_hash_extra_v1_test.vk --vk2 ./meta/v1/to_g2_hash.vk
go run mpccmd.go phase2 contribute --input ./meta/phase2/outer_init.phase2 --output ./meta/phase2/outer_contribute_1.phase2
go run mpccmd.go phase2 verify --input ./meta/phase2/outer_init.phase2 --output ./meta/phase2/outer_contribute_1.phase2
go run mpccmd.go seal --srs ./meta/phase1/groth16.crs --input ./meta/phase2/outer_contribute_1.phase2 --ccs ./meta/v1/verify_header_extra_v1.ccs --pk ./meta/v1/verify_header_extra_v1.pk --vk ./meta/v1/verify_header_extra_v1.vk --contract ./meta/v1/verify_header_extra_v1.sol
echo "neox v1 mpc finish"
#
## v0 phase2
go run mpccmd.go phase2 init inner --circuit rlp --extra v0 --srs ./meta/phase1/groth16.crs --output ./meta/phase2/rlp_init.phase2 --ccs ./meta/v0/rlp_encode_hash_extra_v0_test.ccs
go run mpccmd.go phase2 contribute --input ./meta/phase2/rlp_init.phase2  --output ./meta/phase2/rlp_contribute_1.phase2
go run mpccmd.go phase2 verify --input ./meta/phase2/rlp_init.phase2  --output ./meta/phase2/rlp_contribute_1.phase2
go run mpccmd.go seal --srs ./meta/phase1/groth16.crs --input ./meta/phase2/rlp_contribute_1.phase2 --ccs ./meta/v0/rlp_encode_hash_extra_v0_test.ccs --pk ./meta/v0/rlp_encode_hash_extra_v0_test.pk --vk ./meta/v0/rlp_encode_hash_extra_v0_test.vk
echo "neox v0 rlp mpc finish"
#
go run mpccmd.go phase2 init inner --circuit noSig --extra v0 --srs ./meta/phase1/groth16.crs --output ./meta/phase2/noSig_init.phase2 --ccs ./meta/v0/rlp_encode_noSig_hash_extra_v0_test.ccs
go run mpccmd.go phase2 contribute --input ./meta/phase2/noSig_init.phase2  --output ./meta/phase2/noSig_contribute_1.phase2
go run mpccmd.go phase2 verify --input ./meta/phase2/noSig_init.phase2  --output ./meta/phase2/noSig_contribute_1.phase2
go run mpccmd.go seal --srs ./meta/phase1/groth16.crs --input ./meta/phase2/noSig_contribute_1.phase2 --ccs ./meta/v0/rlp_encode_noSig_hash_extra_v0_test.ccs --pk ./meta/v0/rlp_encode_noSig_hash_extra_v0_test.pk --vk ./meta/v0/rlp_encode_noSig_hash_extra_v0_test.vk
echo "neox v0 noSig mpc finish"
#
go run mpccmd.go phase2 init outer --extra v0 --srs ./meta/phase1/groth16.crs --output ./meta/phase2/outer_init.phase2 --ccs ./meta/v0/verify_header_extra_v0.ccs --ccs1 ./meta/v0/rlp_encode_hash_extra_v0_test.ccs --ccs2 ./meta/v0/rlp_encode_noSig_hash_extra_v0_test.ccs --vk1 ./meta/v0/rlp_encode_hash_extra_v0_test.vk --vk2 ./meta/v0/rlp_encode_noSig_hash_extra_v0_test.vk
go run mpccmd.go phase2 contribute --input ./meta/phase2/outer_init.phase2 --output ./meta/phase2/outer_contribute_1.phase2
go run mpccmd.go phase2 verify --input ./meta/phase2/outer_init.phase2 --output ./meta/phase2/outer_contribute_1.phase2
go run mpccmd.go seal --srs ./meta/phase1/groth16.crs --input ./meta/phase2/outer_contribute_1.phase2 --ccs ./meta/v0/verify_header_extra_v0.ccs --pk ./meta/v0/verify_header_extra_v0.pk --vk ./meta/v0/verify_header_extra_v0.vk --contract ./meta/v0/verify_header_extra_v0.sol
echo "neox v0 mpc finish"



