import hashlib


def calculate_sha256(file_path):
    #Calculate the SHA-256 checksum of a file.
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as file:
            for byte_block in iter(lambda: file.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        print(f"\nError: File not found - {file_path}")
        return None


def compare_checksum(file_path, provided_checksum):
    #Compare the SHA-256 checksum of a file with a provided checksum.
    file_checksum = calculate_sha256(file_path)
    if file_checksum is None:
        return False
    return file_checksum == provided_checksum


# Input file path and the SHA-256 hash to compare
file_path = input("Enter the path of the file: ")
provided_checksum = input("Enter the SHA-256 hash to compare: ")
print("\nCalculating, please wait...")

# Compare checksums
if compare_checksum(file_path, provided_checksum):
    print("\nThe file's SHA-256 checksum MATCHES the provided hash!")
else:
    print("\nThe file's SHA-256 checksum DOES NOT MATCH the provided hash.")

# Wait for the user to press Enter before exiting
input("\nPress Enter to exit...")
