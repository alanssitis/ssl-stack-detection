import matplotlib.pyplot as plt

stacks = ["go", "openssl_1_0_2", "openssl_1_1_1", "openssl_3_1_1", "openssl_3_2_0", "rustls_0_21_7", "rustls_0_22_0"]
accuracies_no_keysize = [0.2032, 0.6573, 0.3816, 0.3397, 0.3468, 0.3843, 0.3783]
accuracies_with_keysize = [0.0778, 0.402, 0.2565, 0.1994, 0.2154, 0.2233, 0.2298]

plt.figure(figsize=(10, 6))

plt.bar(stacks, accuracies_no_keysize, label='Ignoring Keysize in Cipher Suite Algorithms')
plt.bar(stacks, accuracies_with_keysize, label='Keeping Keysize in Cipher Suite Algorithms')

plt.xlabel('TLS Stack')
plt.ylabel('Model Accuracy')
plt.title('KNN Model Accuracy for Predicting Ciphersuite based on Known TLS Stack')
plt.legend()

plt.savefig('ciphersuiteperstack.png')
