using System;
using System.IO;
using System.Security.Cryptography;

namespace Org.Mentalis.Security.Cryptography
{
    public abstract class DiffieHellman : AsymmetricAlgorithm
    {
        private byte[] _keyMaterial;

        public virtual byte[] CreateKeyExchange()
        {
            if (_keyMaterial == null)
            {
                _keyMaterial = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(_keyMaterial);
                }
            }
            return (byte[])_keyMaterial.Clone();
        }

        public virtual byte[] DecryptKeyExchange(byte[] otherPublicValue)
        {
            if (otherPublicValue == null)
                throw new ArgumentNullException("otherPublicValue");

            if (_keyMaterial == null)
                throw new InvalidOperationException("CreateKeyExchange must be called before DecryptKeyExchange.");

            using (var sha256 = SHA256.Create())
            {
                var combined = new byte[_keyMaterial.Length + otherPublicValue.Length];
                Buffer.BlockCopy(_keyMaterial, 0, combined, 0, _keyMaterial.Length);
                Buffer.BlockCopy(otherPublicValue, 0, combined, _keyMaterial.Length, otherPublicValue.Length);
                return sha256.ComputeHash(combined);
            }
        }

        public override string KeyExchangeAlgorithm
        {
            get { return "DiffieHellman"; }
        }

        public override string SignatureAlgorithm
        {
            get { return "SHA256"; }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        public override string ToXmlString(bool includePrivateParameters)
        {
            return string.Empty;
        }

        public override void FromXmlString(string xmlString)
        {
        }
    }

    public class DiffieHellmanManaged : DiffieHellman
    {
        private readonly byte[] _p;
        private readonly byte[] _g;

        public DiffieHellmanManaged(byte[] p, byte[] g, int bitlen)
        {
            _p = p ?? new byte[0];
            _g = g ?? new byte[0];
        }

        public override byte[] CreateKeyExchange()
        {
            return base.CreateKeyExchange();
        }

        public override byte[] DecryptKeyExchange(byte[] otherPublicValue)
        {
            return base.DecryptKeyExchange(otherPublicValue);
        }
    }

    public class HMAC : ICryptoTransform
    {
        private readonly HashAlgorithm _hashAlgorithm;
        private readonly MemoryStream _buffer = new MemoryStream();
        private readonly byte[] _key;
        private byte[] _finalHash;

        public HMAC(HashAlgorithm hashAlgorithm, byte[] key)
        {
            if (hashAlgorithm == null)
                throw new ArgumentNullException("hashAlgorithm");

            _hashAlgorithm = hashAlgorithm;
            _key = key ?? new byte[0];

            var keyed = _hashAlgorithm as KeyedHashAlgorithm;
            if (keyed != null)
            {
                keyed.Key = _key;
            }
        }

        public byte[] Hash
        {
            get { return _finalHash ?? (_finalHash = _hashAlgorithm.Hash); }
        }

        public byte[] Key
        {
            get { return (byte[])_key.Clone(); }
        }

        public void Clear()
        {
            _buffer.SetLength(0);
            _finalHash = null;
            _hashAlgorithm.Initialize();
        }

        public bool CanReuseTransform
        {
            get { return true; }
        }

        public bool CanTransformMultipleBlocks
        {
            get { return false; }
        }

        public int InputBlockSize
        {
            get { return 1; }
        }

        public int OutputBlockSize
        {
            get { return 1; }
        }

        public void Dispose()
        {
            _hashAlgorithm.Dispose();
            _buffer.Dispose();
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputBuffer == null)
                throw new ArgumentNullException("inputBuffer");

            _buffer.Write(inputBuffer, inputOffset, inputCount);
            if (outputBuffer != null)
            {
                Buffer.BlockCopy(inputBuffer, inputOffset, outputBuffer, outputOffset, inputCount);
            }
            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputBuffer != null && inputCount > 0)
            {
                _buffer.Write(inputBuffer, inputOffset, inputCount);
            }

            _finalHash = _hashAlgorithm.ComputeHash(_buffer.ToArray());
            _buffer.SetLength(0);
            return (byte[])_finalHash.Clone();
        }
    }
}
