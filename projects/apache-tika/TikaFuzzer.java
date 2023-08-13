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

import org.apache.tika.Tika;
import org.apache.tika.exception.TikaException;

public class TikaFuzzer {
	private static final Tika tika = new Tika();

	public static void fuzzerTestOneInput(byte[] input) {
		// try to invoke various methods which parse documents/workbooks/slide-shows/...

		try (InputStream str = new ByteArrayInputStream(input)) {
			tika.detect(str);
		} catch (IOException | IllegalArgumentException e) {
			// expected here, Tika throws both types of exceptions here
		}

		try (InputStream str = new ByteArrayInputStream(input)) {
			// using tika.parse() was slow as it creates a new Thread for each iteration
			/*try (Reader reader = tika.parse(str)) {
				char[] bytes = new char[1024];

				// make sure to read all the resulting data
				while (true) {
					int read = reader.read(bytes);
					if (read == -1) {
						break;
					}
				}
			}*/

			tika.parseToString(str);
		} catch (TikaException | IOException | AssertionError e) {
			// expected here, Tika throws both types of exceptions here
		}
	}
}
