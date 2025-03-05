#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <mosquitto.h>
#include <cjson/cJSON.h>
#include <b64/cdecode.h>

char timestamp[20];
char filename[50];
FILE *file;

// base64_decode_len calculates the length of the decoded string
size_t base64_decode_len(const char* encoded_input) {
    size_t length = strlen(encoded_input);
    if (length % 4 != 0) {
        return 0;  // Invalid Base64 string
    }

    size_t padding = 0;
    if (encoded_input[length - 1] == '=') padding++;
    if (encoded_input[length - 2] == '=') padding++;

    return (length * 3) / 4 - padding;
}

// base64_decode performs the decoding of a Base64 string
size_t base64_decode(base64_decodestate* state_in, const char* code_in, size_t length_in, char* plaintext_out) {
    return base64_decode_block(code_in, length_in, plaintext_out, state_in);
}

// Function to decode Base64 payload
int decode_base64(const char *encoded, unsigned char **decoded_payload) {
    if (encoded == NULL) {
        printf("Error: Null encoded string\n");
        return -1;
    }

    base64_decodestate state;
    base64_init_decodestate(&state);

    size_t decoded_len = base64_decode_len(encoded);
    if (decoded_len == 0) {
        printf("Error: Invalid Base64 string or decoding length.\n");
        return -1;
    }

    *decoded_payload = (unsigned char *)malloc(decoded_len);
    if (*decoded_payload == NULL) {
        printf("Error allocating memory for decoded payload.\n");
        return -1;
    }

    decoded_len = base64_decode(&state, encoded, strlen(encoded), (char *)(*decoded_payload));

    // Check if the decoding was successful
    if (decoded_len == 0) {
        printf("Error: Base64 decoding failed.\n");
        free(*decoded_payload); // free memory if decoding failed
        return -1;
    }

    return decoded_len;
}

// Function to generate timestamp (current time)
void get_timestamp(char *timestamp) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);

    // Format the timestamp as: YYYY-MM-DD_HH-MM-SS
    strftime(timestamp, 20, "%Y-%m-%d_%H-%M-%S", tm_info);
}

// Function to save data to a .txt file without JSON formatting
void save_data_to_file(const char *data_str) {
	char loc_timestamp[64];
	
	get_timestamp(loc_timestamp);
	
    if (file == NULL) {
        printf("Error opening file for writing\n");
        return;
    }

    file = fopen(filename, "a");

    // Write the timestamp and raw data (no JSON formatting)
    fprintf(file, "Timestamp: %s\n", loc_timestamp);
    fprintf(file, "Data: %s\n", data_str);

    fclose(file);
}

void on_connect(struct mosquitto *mosq, void *obj, int rc) {
    printf("ID: %d\n", *(int *)obj);
    if (rc) {
        printf("Error with result code: %d\n", rc);
        exit(-1);
    }

    printf("Connected successfully to broker.\n");

    // Subscribe to the TTN topic for your device
    int sub_rc = mosquitto_subscribe(mosq, NULL, "v3/app-test001@ttn/devices/#", 0);
    if (sub_rc == MOSQ_ERR_SUCCESS) {
        printf("Successfully subscribed to topic 'v3/app-test001@ttn/devices/#'\n");
    } else {
        printf("Failed to subscribe to topic 'v3/app-test001@ttn/devices/#'\n");
    }
}

void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg) {
    printf("Received message on topic %s\n", msg->topic);

    cJSON *json = cJSON_Parse((char *)msg->payload);
    if (json == NULL) {
        printf("Error parsing JSON!\n");
        return;
    }

    cJSON *uplink_message = cJSON_GetObjectItemCaseSensitive(json, "uplink_message");
    if (!cJSON_IsObject(uplink_message)) {
        printf("Error: uplink_message is missing or not an object\n");
        cJSON_Delete(json);
        return;
    }

    cJSON *frm_payload = cJSON_GetObjectItemCaseSensitive(uplink_message, "frm_payload");
    if (!cJSON_IsString(frm_payload) || frm_payload->valuestring == NULL) {
        printf("Error: frm_payload is missing or is not a string\n");
        cJSON_Delete(json);
        return;
    }

    unsigned char *decoded_payload = NULL;
    size_t decoded_len = decode_base64(frm_payload->valuestring, &decoded_payload);
    if (decoded_len == 0 || decoded_payload == NULL) {
        printf("Error decoding Base64 payload\n");
        cJSON_Delete(json);
        return;
    }

    // Now decode the second Base64 layer (only if needed)
    unsigned char *second_decoded_payload = NULL;
    size_t second_decoded_len = 0;

    if (decoded_len > 0) {
        second_decoded_len = decode_base64((const char *)decoded_payload, &second_decoded_payload);
    }

    if (second_decoded_len == 0 || second_decoded_payload == NULL) {
        printf("Error decoding second Base64 payload\n");
        free(decoded_payload);  // Free first decoded payload only
        cJSON_Delete(json);
        return;
    }

    // Process the second decoded payload (assume it is JSON)
    cJSON *decoded_json = cJSON_Parse((char *)second_decoded_payload);
    if (decoded_json != NULL) {
        // Successfully parsed JSON, so save the data to the file
        printf("Decoded JSON:\n");
        char *decoded_json_str = cJSON_Print(decoded_json);
        printf("%s\n", decoded_json_str);
        
        save_data_to_file(decoded_json_str);

        // Free memory
        cJSON_free(decoded_json_str);
        cJSON_Delete(decoded_json);
    } else {
        printf("Second decoded payload is not valid JSON\n");
    }

    // Free memory for decoded payloads after processing
    free(decoded_payload);
    free(second_decoded_payload);

    // Clean up cJSON object
    cJSON_Delete(json);
}


void on_log(struct mosquitto *mosq, void *obj, int level, const char *str) {
    // printf("Mosquitto Log: %s\n", str);
}

int main() {
    int rc, id = 12;
    const char *username = "****";  // Replace with your MQTT username
    const char *password = "****";  // Replace with your MQTT password
    const char *hostname = "eu1.cloud.thethings.network";  // Hostname for TTN
    const int port = 8883;  // TLS/SSL port
    const char *ca_cert_path = "****";  // Path to CA certificate (TTN's root CA)

    get_timestamp(timestamp);
    
    // Create a file with the timestamp in its name (use .txt extension)
    snprintf(filename, sizeof(filename), "measurement_data_%s.txt", timestamp);
    // Open the file in append mode
    file = fopen(filename, "a");

    mosquitto_lib_init();

    struct mosquitto *mosq;
    mosq = mosquitto_new("ttn_test", true, &id);

    // Set username and password for authentication
    mosquitto_username_pw_set(mosq, username, password);

    // Set TLS options
    mosquitto_tls_set(mosq, ca_cert_path, NULL, NULL, NULL, NULL);
    mosquitto_tls_insecure_set(mosq, true);  // Disable certificate verification for testing

    // Set callbacks
    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_message_callback_set(mosq, on_message);
    mosquitto_log_callback_set(mosq, on_log); // Set the log callback for debugging

    // Connect to The Things Network using TLS (port 8883)
    rc = mosquitto_connect(mosq, hostname, port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        printf("Could not connect to Broker with return code %d\n", rc);
        return -1;
    } else {
        printf("Successfully connected to the broker!\n");
    }

    // Start receiving messages in a blocking loop    
    while (1) {
        rc = mosquitto_loop(mosq, -1, 1);  // This will block and handle all MQTT events
        if (rc != MOSQ_ERR_SUCCESS) {
            printf("Error in loop: %d\n", rc);
            if (rc == MOSQ_ERR_CONN_LOST || rc == MOSQ_ERR_KEEPALIVE) {
                printf("Connection lost or keepalive error, attempting to reconnect...\n");
                int retries = 0;
                while ((rc = mosquitto_reconnect(mosq)) != MOSQ_ERR_SUCCESS && retries < 5) {
                    printf("Reconnect failed with code %d, retrying...\n", rc);
                    sleep(1);  // Add delay between retries
                    retries++;
                }
                if (rc == MOSQ_ERR_SUCCESS) {
                    printf("Reconnected successfully!\n");
                } else {
                    printf("Reconnect failed after multiple attempts, exiting...\n");
                    break;  // Exit loop after too many failed reconnections
                }
            } else {
                break;  // Exit loop on other errors
            }
        }
    }

    // Stop the loop and disconnect (this part won't be reached without a manual interrupt)
    mosquitto_loop_stop(mosq, true);
    mosquitto_disconnect(mosq);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

    return 0;
}
