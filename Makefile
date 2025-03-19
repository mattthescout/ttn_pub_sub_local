CC = gcc
CFLAGS = -Wall -g
LIBS = -lmosquitto -lcjson -lb64 -lssl -lcrypto


# Directory for object files and final executables
BUILD_DIR = build

# Targets
all: $(BUILD_DIR)/mqtt_pub $(BUILD_DIR)/mqtt_sub $(BUILD_DIR)/sub
	@echo "Build finished!"

# Create build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile object files in the build directory
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE_PATH) -c $< -o $@

# Build mqtt_pub from object files, and remove object file after
$(BUILD_DIR)/mqtt_pub: $(BUILD_DIR)/mqtt_pub.o
	$(CC) $(CFLAGS) $(BUILD_DIR)/mqtt_pub.o -o $(BUILD_DIR)/mqtt_pub $(LIBS)
	rm -f $(BUILD_DIR)/mqtt_pub.o  # Remove object file after building

# Build mqtt_sub from object files, and remove object file after
$(BUILD_DIR)/mqtt_sub: $(BUILD_DIR)/mqtt_sub.o
	$(CC) $(CFLAGS) $(BUILD_DIR)/mqtt_sub.o -o $(BUILD_DIR)/mqtt_sub $(LIBS)
	rm -f $(BUILD_DIR)/mqtt_sub.o  # Remove object file after building

$(BUILD_DIR)/sub: $(BUILD_DIR)/sub.o
	$(CC) $(CFLAGS) $(BUILD_DIR)/sub.o -o $(BUILD_DIR)/sub $(LIBS)
	rm -f $(BUILD_DIR)/sub.o  # Remove object file after building


# Clean up
clean:
	rm -rf $(BUILD_DIR)
	@echo "Cleaned up the build artifacts!"
