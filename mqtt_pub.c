#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <getopt.h>
#include <b64/cencode.h>
#include <time.h>
#include <openssl/evp.h>

#define MQTT_BROKER "192.168.1.245"
#define MQTT_PORT 8883
#define MQTT_USERNAME "default-app"
#define MQTT_PASSWORD "NNSXS.QXTZ7ZJSOXHN2Q2JDZH64KGCF4WR7EUFPVRCG4Q.KWJEI2CTML7YOWYJNKB2UWGZP5GV7ZD2O2MI6IKXSXZV5RRZOQRA"
//#define CA_CERT_PATH "/home/mateusz/libmosquitto_examples/cert/isrgrootx1.pem"  // Path to CA certificate (TTN's root CA)
const char *app_name = "default-app";

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
    //snprintf(topic, sizeof(topic), "v3/app-test001@ttn/devices/%s/down/push", device_name);
    snprintf(topic, sizeof(topic), "v3/%s/devices/%s/down/push", app_name, device_name);

    mosquitto_lib_init();
    mosq = mosquitto_new(NULL, true, NULL);

    if (!mosq) {
        printf("Error creating Mosquitto instance\n");
        return;
    }

    mosquitto_username_pw_set(mosq, MQTT_USERNAME, MQTT_PASSWORD);
    //mosquitto_tls_set(mosq, CA_CERT_PATH, NULL, NULL, NULL, NULL);
    //mosquitto_tls_insecure_set(mosq, true);  // Disable certificate verification for testing
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
    long timestamp = get_timestamp();

    char *meas_period = NULL;
    char *message_type = NULL;  // Variable to hold the message type (C1, C2, C3, C5, etc.)

    // Define the templates for various message types
	const char *update_payload = "{\"update\":{\"timestamp\":\"%s\",\"measPeriod\":\"%s\"}}";
	const char *c1_payload = "{\"CONF\":\"1\"}";
	const char *c2_payload = "{\"GPS\":\"1\"}";
	const char *c3_payload = "{\"GPS\":\"1\"}";  // C3 payload
	const char *c4_payload = "{\"IT\": \"False\", \"ITT\": \"%s\", \"ITW\": \"%llu\"}";  // C4 payload with False
	const char *c5_payload = "{\"IT\": \"True\", \"ITT\": \"%s\", \"ITW\": \"%llu\"}";   // C5 payload with True

    char timestamp_str[20];
    snprintf(timestamp_str, sizeof(timestamp_str), "%ld", timestamp);

    char task_time_str[20];
    snprintf(task_time_str, sizeof(timestamp_str), "%ld", timestamp + (15 * 60));

	long fixed_timestamp = 1742191200;
	//snprintf(task_time_str, sizeof(timestamp_str), "%ld", fixed_timestamp);

    printf("Current timestamp: %ld\n", timestamp);
    printf("Task timestamp: %s\n", task_time_str);

    int opt;
    char device_name[50];
    snprintf(device_name, sizeof(device_name), "default-device");

    while ((opt = getopt(argc, argv, "d:m:c:")) != -1) {  // Added -c option
        switch (opt) {
            case 'd':
                snprintf(device_name, sizeof(device_name), "%s", optarg);
                break;
            case 'm':
                meas_period = optarg;
                break;
            case 'c':
                message_type = optarg;  // Capture message type
                break;
            default:
                fprintf(stderr, "Usage: %s -d device_name -m meas_period -c message_type\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (!meas_period) {
        meas_period = "5";  // Default measurement period
    }

    // Determine the message to encode based on the -c argument
    char data_to_encode[1024];  // Make sure the buffer is large enough

    if (message_type == NULL || strcmp(message_type, "UP") == 0) {
        snprintf(data_to_encode, sizeof(data_to_encode), update_payload, timestamp_str, meas_period);
    } else if (strcmp(message_type, "C1") == 0) {
        snprintf(data_to_encode, sizeof(data_to_encode), "%s", c1_payload);
    } else if (strcmp(message_type, "C2") == 0) {
        snprintf(data_to_encode, sizeof(data_to_encode), "%s", c2_payload);
    } else if (strcmp(message_type, "C3") == 0) {  // Handle C3
        snprintf(data_to_encode, sizeof(data_to_encode), "%s", c3_payload);
    } else if (strcmp(message_type, "C4") == 0) {  // Handle C4 with "False"
        snprintf(data_to_encode, sizeof(data_to_encode), c4_payload, task_time_str, 120);
    } else if (strcmp(message_type, "C5") == 0) {  // Handle C5 with "True"
        snprintf(data_to_encode, sizeof(data_to_encode), c5_payload, task_time_str, 120);
    } else {
        fprintf(stderr, "Error: Unknown message type '%s'\n", message_type);
        return EXIT_FAILURE;
    }

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

//./mqtt_pub -d actuator-device -m 1 -c C5
