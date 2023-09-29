//Credit: Caali
#pragma once

#include <cstdint>
#include <array>

namespace Cryptography
{
	namespace Cryptor
	{


		class Rabbit
		{
		private:
			class Context
			{
			public:
				std::array<uint32_t, 8> X;
				std::array<uint32_t, 8> C;
				uint32_t Carry;

			public:
				Context();
				void nextState();
			};

		private:
			Context mMasterContext;
			Context mWorkContext;
			std::array<uint8_t, 16> mBuffer;
			size_t mBufferIdx = 0;

		public:
			void setKey(const uint8_t* Key, size_t Length);

			void setIV(const uint8_t* IV, size_t Length);

			void apply(uint8_t* Data, size_t Size);
		};


	}
}
