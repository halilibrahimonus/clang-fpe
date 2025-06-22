#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <fpe.h>
#include <sys/time.h>
#include <fpe_locl.h>

#define FPE_BENCHMARK_NUM_ITERATIONS 1000000
#define FPE_BENCHMARK_INPUT_LENGTH   10
#define RAND_SEED                    1

char rchar(int ord) {
    if (ord < 10) {
        return '0' + ord;
    } else if (ord < 36) {
        return 'a' + ord - 10;
    } else if (ord < 62) {
        return 'A' + ord - 36;
    } else {
        perror("Invalid radix");
        return '\0';
    }
}

char rand_char_in_radix(int radix) {
    return rchar(rand() % radix);
}

struct random_texts {
    char **inputs;
    int inputs_len;
    int input_len;
    int radix;
};
typedef struct random_texts random_texts_st;

void random_text_fill(char *dest, int len, int radix) {
    for (int i = 0; i < len; i++) {
        dest[i] = rand_char_in_radix(radix);
    }
}

char *create_random_text(int len, int radix) {
    char *input = malloc((len + 1) * sizeof(char));
    random_text_fill(input, len, radix);
    input[len] = '\0';
    return input;
}

random_texts_st create_random_texts(int num_inputs, int len, int radix)
{
    random_texts_st o;

    char **inputs = malloc(num_inputs * sizeof(char*));
    for (int i = 0; i < num_inputs; i++) {
        inputs[i] = create_random_text(len, radix);
    }

    o.inputs = inputs;
    o.inputs_len = num_inputs;
    o.input_len = len;
    o.radix = radix;

    return o;
}

inline const char *get_random_input(random_texts_st *rt) {
    return rt->inputs[rand() % (rt->inputs_len)];
}

void destroy_random_texts(struct random_texts *rt) {
    for (int i = 0; i < rt->inputs_len; i++) {
        free(rt->inputs[i]);
    }
    free(rt->inputs);
}

typedef enum algorithm_type {
    ALG_FF1,
    ALG_FF3
} algorithm_type_et;

typedef enum op_type {
    OP_ENCRYPT,
    OP_DECRYPT
} op_type_et;

void do_benchmark(algorithm_type_et alg_type, op_type_et op_type, random_texts_st *rt) {
    FPE_KEY *key = (alg_type == ALG_FF1)
        ? FPE_ff1_create_key("2DE79D232DF5585D68CE47882AE256D6", "CBD09280979564", rt->radix)
        : FPE_ff3_create_key("2DE79D232DF5585D68CE47882AE256D6", "CBD09280979564", rt->radix);

    int num_iterations = FPE_BENCHMARK_NUM_ITERATIONS;
    char ciphertext[100];

    clock_t start, end;
    double elapsed_sec;


    const char *alg_type_str = (alg_type == ALG_FF1) ? "ff1" : "ff3";
    const char *op_type_str = (op_type == OP_ENCRYPT) ? "encrypt" : "decrypt";

    printf("Benchmark: %s %s %d-character radix-%d input for %d iterations...", 
        alg_type_str,
        op_type_str,
        rt->input_len,
        rt->radix,
        num_iterations);
    fflush(stdout);

    start = clock();
    if (alg_type == ALG_FF1 && op_type == OP_ENCRYPT)
    {
        for (int i = 0; i < num_iterations; i++) 
        {
            FPE_ff1_encrypt((char*)get_random_input(rt), ciphertext, key);
        }
    } 
    else if (alg_type == ALG_FF1 && op_type == OP_DECRYPT)
    {
        for (int i = 0; i < num_iterations; i++) 
        {
            FPE_ff1_decrypt((char*)get_random_input(rt), ciphertext, key);
        }
    }
    else if (alg_type == ALG_FF3 && op_type == OP_ENCRYPT)
    {
        for (int i = 0; i < num_iterations; i++) 
        {
            FPE_ff3_encrypt((char*)get_random_input(rt), ciphertext, key);
        }
    }
    else if (alg_type == ALG_FF3 && op_type == OP_DECRYPT)
    {
        for (int i = 0; i < num_iterations; i++) 
        {
            FPE_ff3_decrypt((char*)get_random_input(rt), ciphertext, key);
        }
    }
    end = clock();
    elapsed_sec = ((double) (end - start)) / CLOCKS_PER_SEC;
    printf("\t%f seconds\n", elapsed_sec);
    fflush(stdout);

    if (alg_type == ALG_FF1) 
        FPE_ff1_delete_key(key);
    else 
        FPE_ff3_delete_key(key);
}

int benchmark_test() 
{
    srand(RAND_SEED);

    random_texts_st rt10 = create_random_texts(4096, FPE_BENCHMARK_INPUT_LENGTH, 10);
    random_texts_st rt62 = create_random_texts(4096, FPE_BENCHMARK_INPUT_LENGTH, 62);

    do_benchmark(ALG_FF1, OP_ENCRYPT, &rt10);
    do_benchmark(ALG_FF1, OP_DECRYPT, &rt10);
    do_benchmark(ALG_FF1, OP_ENCRYPT, &rt62);
    do_benchmark(ALG_FF1, OP_DECRYPT, &rt62);
    do_benchmark(ALG_FF3, OP_ENCRYPT, &rt10);
    do_benchmark(ALG_FF3, OP_DECRYPT, &rt10);
    do_benchmark(ALG_FF3, OP_ENCRYPT, &rt62);
    do_benchmark(ALG_FF3, OP_DECRYPT, &rt62);

    destroy_random_texts(&rt10);
    destroy_random_texts(&rt62);
    return 0;
}

int main(int argc, char *argv[])
{
    return benchmark_test();
}