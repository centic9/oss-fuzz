import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import org.apache.commons.io.IOUtils;
import org.apache.poi.POIHSSFFuzzer;

public class TestApp {

	public static void main(String[] args) throws IOException {
		try (Stream<Path> stream = Files.walk(Path.of("/opt/jazzer/oss-fuzz/build/corpus/apache-poi"))) {
			AtomicInteger count = new AtomicInteger();

			stream.filter(Files::isRegularFile)
					.parallel()
					.forEach(path -> {
				System.out.println("Handling " + path);
				count.incrementAndGet();
				try {
					byte[] byteArray = IOUtils.toByteArray(new FileInputStream(path.toFile()));
					POIHSSFFuzzer.fuzzerTestOneInput(byteArray);
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			});

			System.out.println("Handled: " + count.get() + " files");
		}
	}
}
