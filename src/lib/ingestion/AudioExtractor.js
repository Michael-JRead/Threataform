/**
 * src/lib/ingestion/AudioExtractor.js
 * Transcribes audio/video files using @xenova/transformers (Whisper tiny).
 * Lazy-loaded — only activates when user uploads audio/video.
 */

let whisperPipeline = null;

async function getWhisper() {
  if (!whisperPipeline) {
    try {
      const { pipeline } = await import('@huggingface/transformers');
      whisperPipeline = await pipeline(
        'automatic-speech-recognition',
        'onnx-community/whisper-tiny.en',
        { dtype: 'fp32' }
      );
    } catch (err) {
      throw new Error(`Whisper not available: ${err.message}. Ensure @huggingface/transformers is installed.`);
    }
  }
  return whisperPipeline;
}

/**
 * Transcribe an audio/video file.
 * @param {File|Blob} input
 * @returns {Promise<{ text, metadata, tables, codeBlocks }>}
 */
export async function extractAudio(input) {
  try {
    const whisper = await getWhisper();

    // Convert to audio data URL for Whisper
    const arrayBuffer = await input.arrayBuffer();
    const blob        = new Blob([arrayBuffer], { type: input.type ?? 'audio/wav' });
    const url         = URL.createObjectURL(blob);

    const result = await whisper(url, {
      return_timestamps: true,
      chunk_length_s: 30,
      stride_length_s: 5,
    });

    URL.revokeObjectURL(url);

    const text = typeof result.text === 'string'
      ? result.text
      : result.chunks?.map(c => c.text).join(' ') ?? '';

    return {
      text: text.trim(),
      metadata: {
        type:     input.type?.startsWith('video') ? 'video' : 'audio',
        filename: input.name ?? 'audio',
        duration: result.chunks?.at(-1)?.timestamp?.[1],
      },
      tables:     [],
      codeBlocks: [],
    };
  } catch (err) {
    return {
      text:       `[Audio transcription failed: ${err.message}]`,
      metadata:   { type: 'audio', error: err.message },
      tables:     [],
      codeBlocks: [],
    };
  }
}
