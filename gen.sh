#!/bin/bash

# Directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Base URL for Lorem Picsum
BASE_URL="https://picsum.photos"

# Number of images to download
IMAGE_COUNT=50

# Function to generate a random size between given ranges
generate_random_size() {
    WIDTH=$((RANDOM % 400 + 100)) # Random width between 100 and 500
    HEIGHT=$((RANDOM % 400 + 100)) # Random height between 100 and 500
    echo "${WIDTH}/${HEIGHT}"
}

# Download loop
for i in $(seq 1 $IMAGE_COUNT); do
    SIZE=$(generate_random_size)
    OUTPUT_FILE="$SCRIPT_DIR/image_$i.jpg"
    echo "Downloading image $i with size $SIZE..."

    # Use wget to handle the redirect and save the final image
    wget -q --show-progress --max-redirect=5 "$BASE_URL/$SIZE" -O "$OUTPUT_FILE"
done

echo "Downloaded $IMAGE_COUNT images with random sizes to $SCRIPT_DIR"
