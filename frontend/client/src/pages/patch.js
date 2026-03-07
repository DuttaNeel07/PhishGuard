const fs = require('fs');
const content = fs.readFileSync('Home.tsx', 'utf8');

// Replace 1
let newContent = content.replace(
    'import { Badge } from "@/components/ui/badge";\n',
    'import { Badge } from "@/components/ui/badge";\nimport { RedirectChain } from "@/components/RedirectChain";\n'
);

// Replace 2
newContent = newContent.replace(
    '              </CardContent>\n            </Card>\n          </motion.div>\n        )}\n      </motion.div>\n',
    `              </CardContent>
            </Card>
            
            {/* Render Redirect Chain if data is available */}
            {result.redirect_chain && result.redirect_chain.chain.length > 0 && (
              <RedirectChain data={result.redirect_chain} />
            )}
          </motion.div>
        )}
      </motion.div>
`
);

fs.writeFileSync('Home.tsx', newContent);
