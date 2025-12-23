const iframe = document.querySelector('iframe.h5p-iframe');
const H5P_iframe = iframe.contentWindow.H5P;
const inst = H5P_iframe.instances[0];

const userInput = prompt("Enter minute to skip to:\n\nExamples:\n- 5.5 = 5 minutes 30 seconds\n- 0.5 = 30 seconds\n- 1 = 1 minute", "5.5");

if (userInput !== null) {
    const minutes = parseFloat(userInput.replace(',', '.'));
    const seconds = Math.round(minutes * 60);
    
    console.log(`⏩ Skipping to ${minutes} minutes (${seconds} seconds)...`);

    const youtubeIframe = iframe.contentWindow.document.querySelector('iframe[src*="youtube"]');
    if (youtubeIframe) {
        console.log("YouTube iframe found:", youtubeIframe);
        
        youtubeIframe.contentWindow.postMessage(
            JSON.stringify({
                event: 'command',
                func: 'seekTo',
                args: [seconds, true]
            }), 
            '*'
        );
        console.log(`✅ YouTube: ${seconds}s (${minutes}m)`);
    }

    if (inst.video && inst.video.seek) {
        console.log("seek method available");
        inst.video.seek(seconds);
        console.log(`✅ H5P: ${seconds}s (${minutes}m)`);
    }

    if (inst.trigger) {
        console.log("trigger method available");
        inst.trigger('seek', seconds);
        console.log(`✅ Trigger: ${seconds}s (${minutes}m)`);
    }

    if (inst.video) {
        console.log("Video status:");
        console.log("- currentTime:", inst.video.currentTime);
        console.log("- duration:", inst.video.duration);
        console.log("- paused:", inst.video.paused);
    }
    
    alert(`Video skipped to ${minutes} minute (${seconds} seconds)!`);
} else {
    console.log("User cancelled.");
}
