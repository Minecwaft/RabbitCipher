//Credit: Caali
#include "Rabbit.h"
#include <boost/endian/conversion.hpp>
#include <bit>

namespace Cryptography
{
	namespace Cryptor
	{

		namespace
		{


			// Square a 32-bit unsigned integer to obtain the 64-bit result and return
			// the upper 32 bits XOR the lower 32 bits
			static uint32_t gFunction(uint32_t x)
			{
				// Construct high and low argument for squaring
				const uint32_t a = x & 0xFFFF;
				const uint32_t b = x >> 16;

				// Calculate high and low result of squaring
				const uint32_t h = (((static_cast<uint32_t>(a * a) >> 17) + static_cast<uint32_t>(a * b)) >> 15) + b * b;
				const uint32_t l = x * x;

				// Return high XOR low
				return h ^ l;
			}


		}


		Rabbit::Context::Context()
			: Carry(0)
		{
			C.fill(0);
			X.fill(0);
		}

		void Rabbit::Context::nextState()
		{
			// Save old counter values
			const auto OldC = C;

			// Calculate new counter values
			C[0] = C[0] + 0x4D34D34D + Carry;
			C[1] = C[1] + 0xD34D34D3 + (C[0] < OldC[0]);
			C[2] = C[2] + 0x34D34D34 + (C[1] < OldC[1]);
			C[3] = C[3] + 0x4D34D34D + (C[2] < OldC[2]);
			C[4] = C[4] + 0xD34D34D3 + (C[3] < OldC[3]);
			C[5] = C[5] + 0x34D34D34 + (C[4] < OldC[4]);
			C[6] = C[6] + 0x4D34D34D + (C[5] < OldC[5]);
			C[7] = C[7] + 0xD34D34D3 + (C[6] < OldC[6]);
			Carry = (C[7] < OldC[7]);

			// Calculate the g-values
			std::array<uint32_t, 8> g;
			for (uint32_t i = 0; i < 8; i++)
				g[i] = gFunction(X[i] + C[i]);

			// Calculate new state values
			X[0] = (g[0] + std::rotl(g[7], 16) + std::rotl(g[6], 16));
			X[1] = (g[1] + std::rotl(g[0], 8) + g[7]);
			X[2] = (g[2] + std::rotl(g[1], 16) + std::rotl(g[0], 16));
			X[3] = (g[3] + std::rotl(g[2], 8) + g[1]);
			X[4] = (g[4] + std::rotl(g[3], 16) + std::rotl(g[2], 16));
			X[5] = (g[5] + std::rotl(g[4], 8) + g[3]);
			X[6] = (g[6] + std::rotl(g[5], 16) + std::rotl(g[4], 16));
			X[7] = (g[7] + std::rotl(g[6], 8) + g[5]);
		}

		void Rabbit::setKey(const uint8_t* Key, size_t Length)
		{
			// Generate four subkeys
			const uint32_t k0 = boost::endian::native_to_little(*reinterpret_cast<const uint32_t*>(&Key[0]));
			const uint32_t k1 = boost::endian::native_to_little(*reinterpret_cast<const uint32_t*>(&Key[4]));
			const uint32_t k2 = boost::endian::native_to_little(*reinterpret_cast<const uint32_t*>(&Key[8]));
			const uint32_t k3 = boost::endian::native_to_little(*reinterpret_cast<const uint32_t*>(&Key[12]));

			// Generate initial state variables
			mMasterContext.X[0] = k0;
			mMasterContext.X[2] = k1;
			mMasterContext.X[4] = k2;
			mMasterContext.X[6] = k3;
			mMasterContext.X[1] = (k3 << 16) | (k2 >> 16);
			mMasterContext.X[3] = (k0 << 16) | (k3 >> 16);
			mMasterContext.X[5] = (k1 << 16) | (k0 >> 16);
			mMasterContext.X[7] = (k2 << 16) | (k1 >> 16);

			// Generate initial counter values
			mMasterContext.C[0] = std::rotl(k2, 16);
			mMasterContext.C[2] = std::rotl(k3, 16);
			mMasterContext.C[4] = std::rotl(k0, 16);
			mMasterContext.C[6] = std::rotl(k1, 16);
			mMasterContext.C[1] = (k0 & 0xFFFF0000) | (k1 & 0xFFFF);
			mMasterContext.C[3] = (k1 & 0xFFFF0000) | (k2 & 0xFFFF);
			mMasterContext.C[5] = (k2 & 0xFFFF0000) | (k3 & 0xFFFF);
			mMasterContext.C[7] = (k3 & 0xFFFF0000) | (k0 & 0xFFFF);

			// Clear carry bit
			mMasterContext.Carry = 0;

			// Iterate the system four times
			for (uint32_t i = 0; i < 4; i++)
				mMasterContext.nextState();

			// Modify the counters
			for (uint32_t i = 0; i < 8; i++)
				mMasterContext.C[i] ^= mMasterContext.X[(i + 4) & 0x7];

			// Copy master instance to work instance
			mWorkContext = mMasterContext;

			mBuffer.fill(0);
			mBufferIdx = 0;
		}

		void Rabbit::setIV(const uint8_t* IV, size_t Length)
		{

			// Generate four subvectors
			const uint32_t i0 = boost::endian::native_to_little(*reinterpret_cast<const uint32_t*>(&IV[0]));
			const uint32_t i2 = boost::endian::native_to_little(*reinterpret_cast<const uint32_t*>(&IV[4]));
			const uint32_t i1 = (i0 >> 16) | (i2 & 0xFFFF0000);
			const uint32_t i3 = (i2 << 16) | (i0 & 0x0000FFFF);

			// Modify counter values
			mWorkContext.C[0] = mMasterContext.C[0] ^ i0;
			mWorkContext.C[1] = mMasterContext.C[1] ^ i1;
			mWorkContext.C[2] = mMasterContext.C[2] ^ i2;
			mWorkContext.C[3] = mMasterContext.C[3] ^ i3;
			mWorkContext.C[4] = mMasterContext.C[4] ^ i0;
			mWorkContext.C[5] = mMasterContext.C[5] ^ i1;
			mWorkContext.C[6] = mMasterContext.C[6] ^ i2;
			mWorkContext.C[7] = mMasterContext.C[7] ^ i3;

			// Copy state variables
			mWorkContext.X = mMasterContext.X;
			mWorkContext.Carry = mMasterContext.Carry;

			// Iterate the system four times
			for (uint32_t i = 0; i < 4; i++)
				mWorkContext.nextState();

			mBuffer.fill(0);
			mBufferIdx = 0;
		}

		void Rabbit::apply(uint8_t* Data, size_t Size)
		{
			if (mBufferIdx > 0)
			{
				while (mBufferIdx < mBuffer.size())
				{
					*Data ^= mBuffer[mBufferIdx];
					++mBufferIdx;
					++Data;
					--Size;
					if (Size == 0)
						break;
				}

				if (mBufferIdx == mBuffer.size())
					mBufferIdx = 0;
			}

			// Encrypt/decrypt all full blocks
			while (Size >= 16)
			{
				// Iterate the system
				mWorkContext.nextState();

				// Encrypt/decrypt 16 bytes of data
				*reinterpret_cast<uint32_t*>(Data + 0) = *reinterpret_cast<const uint32_t*>(Data + 0) ^ boost::endian::native_to_little(mWorkContext.X[0] ^ (mWorkContext.X[5] >> 16) ^ (mWorkContext.X[3] << 16));
				*reinterpret_cast<uint32_t*>(Data + 4) = *reinterpret_cast<const uint32_t*>(Data + 4) ^ boost::endian::native_to_little(mWorkContext.X[2] ^ (mWorkContext.X[7] >> 16) ^ (mWorkContext.X[5] << 16));
				*reinterpret_cast<uint32_t*>(Data + 8) = *reinterpret_cast<const uint32_t*>(Data + 8) ^ boost::endian::native_to_little(mWorkContext.X[4] ^ (mWorkContext.X[1] >> 16) ^ (mWorkContext.X[7] << 16));
				*reinterpret_cast<uint32_t*>(Data + 12) = *reinterpret_cast<const uint32_t*>(Data + 12) ^ boost::endian::native_to_little(mWorkContext.X[6] ^ (mWorkContext.X[3] >> 16) ^ (mWorkContext.X[1] << 16));

				// Increment pointers and decrement length
				Data += 16;
				Size -= 16;
			}

			// Encrypt/decrypt remaining data using buffer
			if (Size > 0)
			{
				// Iterate the system
				mWorkContext.nextState();

				// Fill buffer
				*reinterpret_cast<uint32_t*>(mBuffer.data() + 0) = boost::endian::native_to_little(mWorkContext.X[0] ^ (mWorkContext.X[5] >> 16) ^ (mWorkContext.X[3] << 16));
				*reinterpret_cast<uint32_t*>(mBuffer.data() + 4) = boost::endian::native_to_little(mWorkContext.X[2] ^ (mWorkContext.X[7] >> 16) ^ (mWorkContext.X[5] << 16));
				*reinterpret_cast<uint32_t*>(mBuffer.data() + 8) = boost::endian::native_to_little(mWorkContext.X[4] ^ (mWorkContext.X[1] >> 16) ^ (mWorkContext.X[7] << 16));
				*reinterpret_cast<uint32_t*>(mBuffer.data() + 12) = boost::endian::native_to_little(mWorkContext.X[6] ^ (mWorkContext.X[3] >> 16) ^ (mWorkContext.X[1] << 16));

				// Encrypt/decrypt the data
				for (size_t i = 0; i < Size; i++)
					Data[i] ^= mBuffer[i];
				mBufferIdx = Size;
			}
		}
	}
}
