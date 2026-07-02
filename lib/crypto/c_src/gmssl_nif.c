#include <erl_nif.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) { return 0; }
static int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info) { return 0; }
static void unload(ErlNifEnv* env, void* priv_data) { }

static ERL_NIF_TERM info_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM info_lib_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM info_fips_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM enable_fips_mode_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM hash_algorithms_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM pubkey_algorithms_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM cipher_algorithms_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM mac_algorithms_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM curve_algorithms_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM rsa_opts_algorithms_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM hash_info_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM hash_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary data;
    ERL_NIF_TERM ret;
    unsigned char *outp;
    if (!enif_is_identical(argv[0], enif_make_atom(env, "sm3"))) {
        return enif_raise_exception(env, enif_make_atom(env, "notsup"));
    }
    if (!enif_inspect_iolist_as_binary(env, argv[1], &data)) {
        return enif_make_badarg(env);
    }
    outp = enif_make_new_binary(env, SM3_DIGEST_SIZE, &ret);
    if (!outp) return enif_raise_exception(env, enif_make_atom(env, "error"));
    SM3_CTX sm3_ctx;
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, data.data, data.size);
    sm3_finish(&sm3_ctx, outp);
    return ret;
}
static ERL_NIF_TERM hash_init_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM hash_update_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM hash_final_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM hash_final_xof_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM mac_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM mac_init_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM mac_update_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM mac_final_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM cipher_info_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM ng_crypto_init_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM ng_crypto_update_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM ng_crypto_final_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM ng_crypto_get_data_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM ng_crypto_one_time_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    ErlNifBinary key, iv, data;
    int encrypt = 1;

    if (!enif_is_identical(argv[0], enif_make_atom(env, "sm4_cbc"))) {
        return enif_raise_exception(env, enif_make_atom(env, "notsup"));
    }

    if (!enif_inspect_iolist_as_binary(env, argv[1], &key) ||
        !enif_inspect_iolist_as_binary(env, argv[2], &iv) ||
        !enif_inspect_iolist_as_binary(env, argv[3], &data)) {
        return enif_make_badarg(env);
    }

    if (argv[4] == enif_make_atom(env, "false")) {
        encrypt = 0;
    } else if (enif_is_map(env, argv[4])) {
        ERL_NIF_TERM enc_val;
        if (enif_get_map_value(env, argv[4], enif_make_atom(env, "encrypt"), &enc_val)) {
            if (enc_val == enif_make_atom(env, "false")) {
                encrypt = 0;
            }
        }
    }

    ErlNifBinary out_bin;
    if (!enif_alloc_binary(data.size + 16, &out_bin)) {
        return enif_raise_exception(env, enif_make_atom(env, "error"));
    }

    size_t outlen = 0;
    SM4_KEY sm4_key;
    if (encrypt) {
        sm4_set_encrypt_key(&sm4_key, key.data);
        if (sm4_cbc_padding_encrypt(&sm4_key, iv.data, data.data, data.size, out_bin.data, &outlen) != 1) {
            enif_release_binary(&out_bin);
            return enif_raise_exception(env, enif_make_atom(env, "error"));
        }
    } else {
        sm4_set_decrypt_key(&sm4_key, key.data);
        if (sm4_cbc_padding_decrypt(&sm4_key, iv.data, data.data, data.size, out_bin.data, &outlen) != 1) {
            enif_release_binary(&out_bin);
            return enif_raise_exception(env, enif_make_atom(env, "error"));
        }
    }

    if (!enif_realloc_binary(&out_bin, outlen)) {
        enif_release_binary(&out_bin);
        return enif_raise_exception(env, enif_make_atom(env, "error"));
    }

    return enif_make_binary(env, &out_bin);
}
static ERL_NIF_TERM strong_rand_bytes_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM strong_rand_range_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM rand_uniform_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM mod_exp_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM do_exor_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM hash_equals_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM pbkdf2_hmac_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM pkey_sign_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM pkey_sign_heavy_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM pkey_verify_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM pkey_crypt_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM encapsulate_key_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM decapsulate_key_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM kem_algorithms_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM rsa_generate_key_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM dh_generate_key_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM dh_compute_key_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM evp_compute_key_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM evp_generate_key_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM privkey_to_pubkey_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM srp_value_B_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM srp_user_secret_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM srp_host_secret_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM ec_generate_key_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM ecdh_compute_key_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM rand_seed_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM aead_cipher_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM aead_cipher_init_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_by_id_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_init_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_free_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_load_dynamic_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_ctrl_cmd_strings_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_register_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_unregister_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_add_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_remove_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_get_first_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_get_next_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_get_id_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_get_name_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM engine_get_all_methods_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }
static ERL_NIF_TERM ensure_engine_loaded_nif_stub(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) { return enif_raise_exception(env, enif_make_atom(env, "notsup")); }

static ErlNifFunc nif_funcs[] = {
    {"info_nif", 0, info_nif_stub, 0},
    {"info_lib", 0, info_lib_stub, 0},
    {"info_fips", 0, info_fips_stub, 0},
    {"enable_fips_mode_nif", 1, enable_fips_mode_nif_stub, 0},
    {"hash_algorithms", 0, hash_algorithms_stub, 0},
    {"pubkey_algorithms", 0, pubkey_algorithms_stub, 0},
    {"cipher_algorithms", 0, cipher_algorithms_stub, 0},
    {"mac_algorithms", 0, mac_algorithms_stub, 0},
    {"curve_algorithms", 0, curve_algorithms_stub, 0},
    {"rsa_opts_algorithms", 0, rsa_opts_algorithms_stub, 0},
    {"hash_info", 1, hash_info_stub, 0},
    {"hash_nif", 2, hash_nif_stub, 0},
    {"hash_init_nif", 1, hash_init_nif_stub, 0},
    {"hash_update_nif", 2, hash_update_nif_stub, 0},
    {"hash_final_nif", 1, hash_final_nif_stub, 0},
    {"hash_final_xof_nif", 2, hash_final_xof_nif_stub, 0},
    {"mac_nif", 4, mac_nif_stub, 0},
    {"mac_init_nif", 3, mac_init_nif_stub, 0},
    {"mac_update_nif", 2, mac_update_nif_stub, 0},
    {"mac_final_nif", 1, mac_final_nif_stub, 0},
    {"cipher_info_nif", 1, cipher_info_nif_stub, 0},
    {"ng_crypto_init_nif", 4, ng_crypto_init_nif_stub, 0},
    {"ng_crypto_update_nif", 2, ng_crypto_update_nif_stub, 0},
    {"ng_crypto_final_nif", 1, ng_crypto_final_nif_stub, 0},
    {"ng_crypto_get_data_nif", 1, ng_crypto_get_data_nif_stub, 0},
    {"ng_crypto_one_time_nif", 5, ng_crypto_one_time_nif_stub, 0},
    {"strong_rand_bytes_nif", 1, strong_rand_bytes_nif_stub, 0},
    {"strong_rand_range_nif", 1, strong_rand_range_nif_stub, 0},
    {"rand_uniform_nif", 2, rand_uniform_nif_stub, 0},
    {"mod_exp_nif", 4, mod_exp_nif_stub, 0},
    {"do_exor", 2, do_exor_stub, 0},
    {"hash_equals_nif", 2, hash_equals_nif_stub, 0},
    {"pbkdf2_hmac_nif", 5, pbkdf2_hmac_nif_stub, 0},
    {"pkey_sign_nif", 5, pkey_sign_nif_stub, 0},
    {"pkey_sign_heavy_nif", 5, pkey_sign_heavy_nif_stub, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"pkey_verify_nif", 6, pkey_verify_nif_stub, 0},
    {"pkey_crypt_nif", 6, pkey_crypt_nif_stub, 0},
    {"encapsulate_key_nif", 2, encapsulate_key_nif_stub, 0},
    {"decapsulate_key_nif", 3, decapsulate_key_nif_stub, 0},
    {"kem_algorithms_nif", 0, kem_algorithms_nif_stub, 0},
    {"rsa_generate_key_nif", 2, rsa_generate_key_nif_stub, 0},
    {"dh_generate_key_nif", 4, dh_generate_key_nif_stub, 0},
    {"dh_compute_key_nif", 3, dh_compute_key_nif_stub, 0},
    {"evp_compute_key_nif", 3, evp_compute_key_nif_stub, 0},
    {"evp_generate_key_nif", 2, evp_generate_key_nif_stub, 0},
    {"privkey_to_pubkey_nif", 2, privkey_to_pubkey_nif_stub, 0},
    {"srp_value_B_nif", 5, srp_value_B_nif_stub, 0},
    {"srp_user_secret_nif", 7, srp_user_secret_nif_stub, 0},
    {"srp_host_secret_nif", 5, srp_host_secret_nif_stub, 0},
    {"ec_generate_key_nif", 2, ec_generate_key_nif_stub, 0},
    {"ecdh_compute_key_nif", 3, ecdh_compute_key_nif_stub, 0},
    {"rand_seed_nif", 1, rand_seed_nif_stub, 0},
    {"aead_cipher_nif", 7, aead_cipher_nif_stub, 0},
    {"aead_cipher_nif", 4, aead_cipher_nif_stub, 0},
    {"aead_cipher_init_nif", 4, aead_cipher_init_nif_stub, 0},
    {"engine_by_id_nif", 1, engine_by_id_nif_stub, 0},
    {"engine_init_nif", 1, engine_init_nif_stub, 0},
    {"engine_free_nif", 1, engine_free_nif_stub, 0},
    {"engine_load_dynamic_nif", 0, engine_load_dynamic_nif_stub, 0},
    {"engine_ctrl_cmd_strings_nif", 3, engine_ctrl_cmd_strings_nif_stub, 0},
    {"engine_register_nif", 2, engine_register_nif_stub, 0},
    {"engine_unregister_nif", 2, engine_unregister_nif_stub, 0},
    {"engine_add_nif", 1, engine_add_nif_stub, 0},
    {"engine_remove_nif", 1, engine_remove_nif_stub, 0},
    {"engine_get_first_nif", 0, engine_get_first_nif_stub, 0},
    {"engine_get_next_nif", 1, engine_get_next_nif_stub, 0},
    {"engine_get_id_nif", 1, engine_get_id_nif_stub, 0},
    {"engine_get_name_nif", 1, engine_get_name_nif_stub, 0},
    {"engine_get_all_methods_nif", 0, engine_get_all_methods_nif_stub, 0},
    {"ensure_engine_loaded_nif", 2, ensure_engine_loaded_nif_stub, 0},
};

ERL_NIF_INIT(crypto, nif_funcs, load, NULL, upgrade, unload)
