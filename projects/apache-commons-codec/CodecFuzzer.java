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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.codec.CodecPolicy;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base32InputStream;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Hex;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * This class provides a simple target for fuzzing Apache Commons Codec with Jazzer.
 * <p>
 * It uses the fuzzed input data to try to base64 encode/decode data.
 * <p>
 * It catches all exceptions that are currently expected.
 */
public class CodecFuzzer {

	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		int lineLength = data.consumeInt();
		byte[] lineSeparator = data.consumeBytes(10);
		boolean useHex = data.consumeBoolean();
		byte bytePadding = data.consumeByte();
		CodecPolicy policy = CodecPolicy.values()[data.consumeInt(0, CodecPolicy.values().length-1)];
		String hex = data.consumeString(10);

		byte[] bytes = data.consumeRemainingAsBytes();

		// don't try to handle null-byte-array
		if (bytes == null) {
			return;
		}

		// try to invoke various methods which read archive data
		try {
			Base32InputStream stream = new Base32InputStream(new ByteArrayInputStream(bytes));
			consume(stream);
		} catch (IOException e) {
			// expected here
		}

		try {
			Base32 base32 = new Base32(lineLength, lineSeparator, useHex, bytePadding);
			base32.decode(bytes);
		} catch (IllegalArgumentException e) {
			// expected here
		}
		try {
			Base32 base32 = new Base32(lineLength, lineSeparator, useHex, bytePadding);
			base32.encode(bytes);
		} catch (IllegalArgumentException e) {
			// expected here
		}

		// try to invoke various methods which read archive data
		try {
			Base64InputStream stream = new Base64InputStream(new ByteArrayInputStream(bytes));
			consume(stream);
		} catch (IOException e) {
			// expected here
		}

		try {
			Base64 base64 = new Base64(lineLength, lineSeparator, useHex, policy);
			base64.decode(bytes);
		} catch (IllegalArgumentException e) {
			// expected here
		}
		try {
			Base64 base64 = new Base64(lineLength, lineSeparator, useHex, policy);
			base64.encode(bytes);
		} catch (IllegalArgumentException e) {
			// expected here
		}

		try {
			Hex.decodeHex(Hex.encodeHex(bytes));
		} catch (DecoderException e) {
			// expected here
		}

		try {
			Hex.decodeHex(hex);
		} catch (DecoderException e) {
			// expected here
		}
	}

	private static void consume(InputStream stream) throws IOException {
		byte[] bytesRead = new byte[1024];
		while (true) {
			int read = stream.read(bytesRead);
			if (read < 0) {
				break;
			}
		}
	}
}
