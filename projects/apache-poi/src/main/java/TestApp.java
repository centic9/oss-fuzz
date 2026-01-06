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

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import org.apache.commons.io.IOUtils;
import org.apache.poi.POIFileHandlerFuzzer;

public class TestApp {

	public static void main(String[] args) throws IOException {
		try (Stream<Path> stream = Files.walk(Path.of("/opt/jazzer/oss-fuzz/build/corpus/apache-poi"))) {
			AtomicInteger count = new AtomicInteger();

			stream.filter(Files::isRegularFile)
					.parallel()
					.forEach(path -> {
				System.out.println(count.incrementAndGet() + " - Handling " + path);

				try {
					byte[] byteArray = IOUtils.toByteArray(new FileInputStream(path.toFile()));
					POIFileHandlerFuzzer.fuzzerTestOneInput(byteArray);
				} catch (Exception e) {
					throw new RuntimeException("While handling file: " + path, e);
				}
			});

			System.out.println("Handled: " + count.get() + " files");
		}
	}
}
