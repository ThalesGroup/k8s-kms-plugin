package gose

// AsymmetricDecryptionKeyStoreImpl implements the AsymmetricDecryptionKeyStore interface providing AsymmetricDecryptionKey
// lookup capabilities.
type AsymmetricDecryptionKeyStoreImpl struct {
	keys map[string]AsymmetricDecryptionKey
}

// Get returns a matching AsymmetricDecryptionKey fpr the given Key ID or an error (ErrUnknownKey) if the requested key
// cannot be found.
func (a *AsymmetricDecryptionKeyStoreImpl) Get(kid string) (k AsymmetricDecryptionKey, err error) {
	// Find returns the key with matching kid or, if there's only a single key, return that.
	if key, ok := a.keys[kid]; ok {
		return key, nil
	}
	if len(a.keys) == 1 {
		for _, key := range a.keys {
			return key, nil
		}
	}
	return nil, ErrUnknownKey
}

// NewAsymmetricDecryptionKeyStoreImpl creates a AsymmetricDecryptionKeyStoreImpl instances with the given keys.
func NewAsymmetricDecryptionKeyStoreImpl(keys map[string]AsymmetricDecryptionKey) (*AsymmetricDecryptionKeyStoreImpl, error) {
	return &AsymmetricDecryptionKeyStoreImpl{
		keys: keys,
	}, nil
}