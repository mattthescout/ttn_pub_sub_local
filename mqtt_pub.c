#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <getopt.h>
#include <b64/cencode.h>
#include <time.h>
#include <openssl/evp.h>

#define MQTT_BROKER "eu1.cloud.thethings.network"
#define MQTT_PORT 8883
#define MQTT_USERNAME "****"
#define MQTT_PASSWORD "****"
#define CA_CERT_PATH "*****"  // Path to CA certificate (TTN's root CA)

long get_timestamp() {
    return time(NULL);  // Return current timestamp in seconds
}

char* base64_encode(const unsigned char *input, size_t length) {
    size_t encoded_len = 4 * ((length + 2) / 3);  // Base64 encoding length
    char *encoded = (char *)malloc(encoded_len + 1);  // +1 for the null terminator

    // Ensure memory allocation succeeded
    if (!encoded) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Use OpenSSL to base64 encode without line breaks
    EVP_EncodeBlock((unsigned char *)encoded, input, length);

    return encoded;
}

void on_log(struct mosquitto *mosq, void *obj, int level, const char *str) {
    printf("Mosquitto log: %s\n", str);
}

void mqtt_publish(const char *device_name, const char *json_payload) {
    struct mosquitto *mosq;
    int rc;
    char topic[100];
    snprintf(topic, sizeof(topic), "v3/app-test001@ttn/devices/%s/down/push", device_name);

    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, true, NULL);

    if (!mosq) {
        printf("Error creating Mosquitto instance\n");
        return;
    }

    mosquitto_username_pw_set(mosq, MQTT_USERNAME, MQTT_PASSWORD);
    mosquitto_tls_set(mosq, CA_CERT_PATH, NULL, NULL, NULL, NULL);
    mosquitto_tls_insecure_set(mosq, true);  // Disable certificate verification for testing
    mosquitto_log_callback_set(mosq, on_log);

    rc = mosquitto_connect(mosq, MQTT_BROKER, MQTT_PORT, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("Error: Could not connect to the broker (Code: %d)\n", rc);
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return;
    }

    printf("Connected to the broker successfully!\n");

    rc = mosquitto_loop_start(mosq);  // Start a background loop to process any events
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("Error: Failed to start the loop (Code: %d)\n", rc);
        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return;
    }

    rc = mosquitto_publish(mosq, NULL, topic, strlen(json_payload), json_payload, 0, false);
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("Error: Failed to publish message (Code: %d)\n", rc);
    } else {
        printf("Message published successfully to topic: %s\n", topic);
    }

    mosquitto_loop_stop(mosq, false);  // Stop the loop after publishing
    mosquitto_disconnect(mosq);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
}

int main(int argc, char *argv[]) {
    char *meas_period = NULL;
    const char *data_to_encode_template = "{\"config\":{\"timestamp\":\"%s\",\"measPeriod\":\"%s\",\"action\":\"open\"}}";

    long timestamp = get_timestamp();

    char timestamp_str[20];
    snprintf(timestamp_str, sizeof(timestamp_str), "%ld", timestamp);

    int opt;
    char device_name[50];
    snprintf(device_name, sizeof(device_name), "default-device");

    while ((opt = getopt(argc, argv, "d:m:")) != -1) {
        switch (opt) {
            case 'd':
                snprintf(device_name, sizeof(device_name), "%s", optarg);
                break;
            case 'm':
                meas_period = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -d device_name -m meas_period\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!meas_period) {
        meas_period = "5";  // Default measurement period
    }

    char data_to_encode[1024];  // Make sure the buffer is large enough
    snprintf(data_to_encode, sizeof(data_to_encode), data_to_encode_template, timestamp_str, meas_period);

    // Check the length before encoding
    size_t data_length = strlen(data_to_encode);
    printf("Data length before encoding: %zu\n", data_length);
    printf("Data to encode: %s\n", data_to_encode);

    // Perform the encoding
    char *encoded_payload = base64_encode((unsigned char *)data_to_encode, data_length);

    printf("Base64 encoded payload: %s\n", encoded_payload);
    printf("Length of encoded payload: %zu\n", strlen(encoded_payload));

    // Increase the buffer size to ensure we can hold larger payloads
    char json_payload[2048];  // Increased buffer size

    int written = snprintf(json_payload, sizeof(json_payload),
        "{"
            "\"downlinks\": ["
                "{"
                    "\"f_port\": 15,"
                    "\"frm_payload\": \"%s\","
                    "\"priority\": \"NORMAL\""
                "}"
            "]"
        "}", encoded_payload);

    if (written < 0 || written >= sizeof(json_payload)) {
        fprintf(stderr, "Error formatting JSON payload\n");
        return EXIT_FAILURE;
    }

    free(encoded_payload);
    printf("Final JSON Payload: %s\n", json_payload);

    printf("Publishing message to device: %s\n", device_name);
    mqtt_publish(device_name, json_payload);

    return 0;
}
