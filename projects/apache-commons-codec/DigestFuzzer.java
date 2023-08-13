// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.digest.Blake3;
import org.apache.commons.codec.digest.Crypt;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacAlgorithms;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.codec.digest.Md5Crypt;
import org.apache.commons.codec.digest.MurmurHash2;
import org.apache.commons.codec.digest.MurmurHash3;
import org.apache.commons.codec.digest.PureJavaCrc32;
import org.apache.commons.codec.digest.PureJavaCrc32C;
import org.apache.commons.codec.digest.Sha2Crypt;
import org.apache.commons.codec.digest.UnixCrypt;
import org.apache.commons.codec.digest.XXHash32;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * This class provides a simple target for fuzzing Apache Commons Codec with Jazzer.
 * <p>
 * It uses the fuzzed input data to trigger classes in the package "digest".
 * <p>
 * It catches all exceptions that are currently expected.
 */
public class DigestFuzzer {

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		try {
			switch (data.consumeInt(0, 15)) {
				case 0: {
					Blake3 hasher = Blake3.initHash();
					hasher.update("Hello, world!".getBytes(StandardCharsets.UTF_8));
					byte[] hash = new byte[32];
					hasher.doFinalize(hash);
					break;
				}
				case 1:
					Crypt.crypt(data.consumeRemainingAsString());
					break;
				case 2:
					Crypt.crypt(data.consumeString(100), data.consumeString(10));
					break;
				case 3:
					new DigestUtils(data.consumeString(100)).digest(data.consumeRemainingAsBytes());
					break;
				case 4:
					byte[] key = data.consumeBytes(10);
					HmacAlgorithms algo = HmacAlgorithms.values()[data.consumeInt(0, HmacAlgorithms.values().length-1)];
					String valueToDigest = data.consumeRemainingAsString();
					new HmacUtils(algo, key).hmac(valueToDigest);
					break;
				case 5:
					Md5Crypt.apr1Crypt(data.consumeRemainingAsBytes());
					break;
				case 6:
					Md5Crypt.md5Crypt(data.consumeRemainingAsBytes());
					break;
				case 7:
					MurmurHash2.hash32(data.consumeRemainingAsString());
					break;
				case 8: {
					byte[] bytes = data.consumeRemainingAsBytes();
					//noinspection ResultOfMethodCallIgnored
					MurmurHash2.hash64(bytes, bytes.length);
					break;
				}
				case 9:
					//noinspection deprecation
					MurmurHash3.hash32(data.consumeRemainingAsString());
					break;
				case 10: {
					byte[] bytes = data.consumeRemainingAsBytes();
					//noinspection deprecation,ResultOfMethodCallIgnored
					MurmurHash3.hash64(bytes);
					break;
				}
				case 11: {
					PureJavaCrc32 crc = new PureJavaCrc32();
					crc.update(data.consumeByte());
					crc.reset();
					crc.update(data.consumeRemainingAsBytes());
					break;
				}
				case 12: {
					PureJavaCrc32C crc = new PureJavaCrc32C();
					crc.update(data.consumeByte());
					crc.reset();
					crc.update(data.consumeRemainingAsBytes());
					break;
				}
				case 13:
					Sha2Crypt.sha256Crypt(data.consumeRemainingAsBytes());
					break;
				case 14:
					UnixCrypt.crypt(data.consumeRemainingAsBytes());
					break;
				case 15:
					XXHash32 hasher = new XXHash32();
					hasher.update(data.consumeByte());
					hasher.update(data.consumeRemainingAsBytes());
					break;
				default:
					throw new UnsupportedOperationException();
			}
		} catch (IllegalArgumentException e) {
			// ignored
		}
	}
}
